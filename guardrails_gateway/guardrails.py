"""Deterministic, config-driven guardrails. No network, no LLM calls here.

Every guardrail is a pure function over text + policy and contributes to a
Verdict (allow / redact / block) with human-readable reasons. These are
HEURISTIC defenses (curated regex + simple phrase matching), not a guarantee.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_POLICY_PATH = Path(__file__).parent / "policy.yaml"

# --- PII detectors (curated regex, not ML NER). ponytail: regex over NER;
# swap in a spaCy/presidio model only if recall on free-form names matters. ---
PII_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    # 13-19 digits with optional space/dash separators; Luhn-checked below.
    "credit_card": re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
    "phone": re.compile(
        r"(?<!\d)(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
    ),
}

# Secret patterns for OUTPUT egress checks.
SECRET_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "private_key_header": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "openai_api_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}


@dataclass
class Finding:
    type: str
    start: int
    end: int
    value: str


@dataclass
class Verdict:
    action: str  # "allow" | "redact" | "block"
    text: str  # possibly-redacted text
    reasons: List[Dict[str, str]] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)


def luhn_ok(digits: str) -> bool:
    """True if `digits` passes the Luhn checksum and is a plausible card length."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_pii(text: str, types: List[str]) -> List[Finding]:
    """Return non-overlapping PII findings for the requested types.

    Overlaps are resolved longest-match-wins so a 16-digit card is not also
    reported as a phone number.
    """
    raw: List[Finding] = []
    for t in types:
        pat = PII_PATTERNS.get(t)
        if not pat:
            continue
        for m in pat.finditer(text):
            if t == "credit_card" and not luhn_ok(re.sub(r"\D", "", m.group())):
                continue
            raw.append(Finding(t, m.start(), m.end(), m.group()))

    chosen: List[Finding] = []
    last_end = -1
    for f in sorted(raw, key=lambda f: (f.start, -(f.end - f.start))):
        if f.start >= last_end:
            chosen.append(f)
            last_end = f.end
    return chosen


def redact(text: str, findings: List[Finding]) -> str:
    out: List[str] = []
    i = 0
    for f in sorted(findings, key=lambda f: f.start):
        out.append(text[i:f.start])
        out.append(f"[REDACTED_{f.type.upper()}]")
        i = f.end
    out.append(text[i:])
    return "".join(out)


def redact_pii_text(text: str, policy: Dict[str, Any]) -> str:
    """Convenience: redact configured PII types in `text`, no block logic."""
    findings = detect_pii(text, policy.get("pii", {}).get("redact", []))
    return redact(text, findings) if findings else text


def find_phrases(text: str, phrases: List[str]) -> List[str]:
    low = text.lower()
    return [p for p in phrases if p.lower() in low]


def detect_secrets(text: str) -> List[str]:
    return [name for name, pat in SECRET_PATTERNS.items() if pat.search(text)]


def _pii_findings_payload(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [{"type": f.type, "start": f.start, "end": f.end} for f in findings]


def check_input(text: str, policy: Dict[str, Any]) -> Verdict:
    """Input guardrails: redact PII, block on injection / banned topics."""
    reasons: List[Dict[str, str]] = []
    findings: Dict[str, Any] = {}
    action = "allow"
    out_text = text

    pii_types = policy.get("pii", {}).get("redact", [])
    pii = detect_pii(text, pii_types)
    if pii:
        out_text = redact(text, pii)
        action = "redact"
        counts: Dict[str, int] = {}
        for f in pii:
            counts[f.type] = counts.get(f.type, 0) + 1
        findings["pii"] = _pii_findings_payload(pii)
        reasons.append(
            {"rule": "pii_redaction", "detail": f"redacted {len(pii)} PII item(s): {counts}"}
        )

    inj = policy.get("injection", {})
    if inj.get("block"):
        hits = find_phrases(text, inj.get("phrases", []))
        if hits:
            findings["injection"] = hits
            reasons.append({"rule": "prompt_injection", "detail": f"matched: {hits}"})
            action = "block"

    ban = policy.get("banned_topics", {})
    if ban.get("block"):
        hits = find_phrases(text, ban.get("keywords", []))
        if hits:
            findings["banned_topics"] = hits
            reasons.append({"rule": "banned_topics", "detail": f"matched: {hits}"})
            action = "block"

    return Verdict(action, out_text, reasons, findings)


def check_output(
    text: str, policy: Dict[str, Any], schema: Optional[Dict[str, Any]] = None
) -> Verdict:
    """Output guardrails: block on PII leak, secret egress, over-length,
    or (when the caller asked for structured output) invalid JSON schema."""
    reasons: List[Dict[str, str]] = []
    findings: Dict[str, Any] = {}
    action = "allow"
    out_cfg = policy.get("output", {})

    if policy.get("pii", {}).get("block_on_output_leak"):
        leak = detect_pii(text, policy.get("pii", {}).get("redact", []))
        if leak:
            findings["pii_leak"] = _pii_findings_payload(leak)
            reasons.append(
                {"rule": "pii_egress", "detail": f"{len(leak)} PII item(s) in output"}
            )
            action = "block"

    secrets = detect_secrets(text)
    if secrets:
        findings["secrets"] = secrets
        reasons.append({"rule": "secret_egress", "detail": f"matched: {secrets}"})
        action = "block"

    maxlen = out_cfg.get("max_length")
    if maxlen and len(text) > maxlen:
        reasons.append(
            {"rule": "max_length", "detail": f"output length {len(text)} > {maxlen}"}
        )
        action = "block"

    if schema is not None:
        from jsonschema import ValidationError, validate

        try:
            validate(json.loads(text), schema)
        except (json.JSONDecodeError, ValidationError) as e:
            findings["schema"] = str(e).splitlines()[0][:200]
            reasons.append(
                {"rule": "json_schema", "detail": "output failed schema validation"}
            )
            action = "block"

    return Verdict(action, text, reasons, findings)


def load_policy(path: Optional[str] = None) -> Dict[str, Any]:
    p = Path(path or os.getenv("GATEWAY_POLICY") or DEFAULT_POLICY_PATH)
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
