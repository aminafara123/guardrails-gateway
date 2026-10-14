"""FastAPI service: an OpenAI-compatible safety proxy + a standalone /guard/check.

Clients point at POST /v1/chat/completions instead of the real provider. The
gateway runs INPUT guardrails on the prompt, forwards the (possibly redacted)
request upstream via llm.py, then runs OUTPUT guardrails before returning.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import llm
from .guardrails import check_input, check_output, load_policy, redact_pii_text

app = FastAPI(title="guardrails-gateway", version="0.1.0")
POLICY = load_policy()

NOTE = (
    "AI-generated output passed through heuristic guardrails (curated regex + "
    "phrase matching). These are triage aids, NOT a guarantee. A human must review."
)


class ChatRequest(BaseModel):
    model_config = {"extra": "allow"}  # pass through temperature, top_p, etc.
    model: Optional[str] = None
    messages: List[Dict[str, Any]]
    response_format: Optional[Dict[str, Any]] = None


class GuardRequest(BaseModel):
    text: str
    stage: str = "input"  # "input" | "output"
    json_schema: Optional[Dict[str, Any]] = None


def _refusal(model: str, reasons: List[Dict[str, str]], stage: str) -> Dict[str, Any]:
    detail = "; ".join(r["detail"] for r in reasons) or "policy violation"
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        f"[guardrails-gateway] Request blocked by {stage} guardrails. "
                        f"This is a heuristic safety decision; a human should review. "
                        f"Reasons: {detail}"
                    ),
                },
                "finish_reason": "content_filter",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "guardrails": {"action": "block", "stage": stage, "reasons": reasons, "note": NOTE},
    }


def _extract_schema(response_format: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not response_format or response_format.get("type") != "json_schema":
        return None
    js = response_format.get("json_schema", {})
    return js.get("schema", js) or None


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": "guardrails-gateway",
        "version": app.version,
        "endpoints": ["/v1/chat/completions", "/guard/check"],
        "note": NOTE,
    }


@app.post("/guard/check")
def guard_check(req: GuardRequest) -> Dict[str, Any]:
    """Run guardrails on arbitrary text and return the verdict. No LLM call."""
    if req.stage == "output":
        v = check_output(req.text, POLICY, schema=req.json_schema)
    else:
        v = check_input(req.text, POLICY)
    return {
        "action": v.action,
        "redacted_text": v.text,
        "reasons": v.reasons,
        "findings": v.findings,
        "note": NOTE,
    }


@app.post("/v1/chat/completions")
def chat_completions(req: ChatRequest):
    # ponytail: non-streaming only. Streaming would require tee-ing the SSE
    # chunks through the output guardrails incrementally (buffer-and-scan, or
    # per-chunk redaction with a trailing overlap window). Out of scope.
    model = req.model or os.getenv("LLM_MODEL") or "unknown"
    messages: List[Dict[str, Any]] = [dict(m) for m in req.messages]

    # INPUT guardrails: block decision over all message content.
    combined = "\n".join(str(m.get("content", "")) for m in messages)
    verdict_in = check_input(combined, POLICY)
    if verdict_in.action == "block":
        return _refusal(model, verdict_in.reasons, "input")

    # Redact PII inside each message so the forwarded request stays well-formed.
    for m in messages:
        if isinstance(m.get("content"), str):
            m["content"] = redact_pii_text(m["content"], POLICY)

    schema = _extract_schema(req.response_format)

    try:
        upstream = llm.chat(messages, model=req.model, response_format=req.response_format)
    except llm.LLMError as e:
        return JSONResponse(
            status_code=502,
            content={
                "error": {"message": str(e), "type": "upstream_unreachable"},
                "guardrails": {"note": NOTE},
            },
        )

    content = upstream.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
    verdict_out = check_output(content, POLICY, schema=schema)
    if verdict_out.action == "block":
        return _refusal(model, verdict_out.reasons, "output")

    upstream["guardrails"] = {
        "action": "allow",
        "input": {"action": verdict_in.action, "reasons": verdict_in.reasons},
        "output": {"action": verdict_out.action, "reasons": verdict_out.reasons},
        "note": NOTE,
    }
    return upstream


def main() -> None:
    """Console entry point: launch the server (uvicorn)."""
    import uvicorn

    host = os.getenv("GATEWAY_HOST", "127.0.0.1")
    port = int(os.getenv("GATEWAY_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
