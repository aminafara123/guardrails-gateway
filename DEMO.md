# 60-second demo script

Goal: show the gateway catching PII, prompt injection, and a secret leak, all deterministically.

## Setup (before recording)
```bash
make install
```
Open two panes: one for the server, one for `curl`.

## Recording (~60s)

1. **Prove the gate is green (5s).** Say "all guardrails are tested offline, no key, no network."
   ```bash
   make test
   ```
   Point at `20 passed`.

2. **Start the gateway (5s).**
   ```bash
   make run
   ```

3. **PII redaction with no LLM call (15s).** Show `/guard/check` scrubbing an email + card and returning exact spans.
   ```bash
   curl -s localhost:8000/guard/check \
     -H 'content-type: application/json' \
     -d @samples/requests/guard_check_pii.json | python3 -m json.tool
   ```
   Highlight `"action": "redact"` and `[REDACTED_EMAIL]`.

4. **Prompt injection is blocked and short-circuits (15s).** Note it never reaches the model.
   ```bash
   curl -s localhost:8000/v1/chat/completions \
     -H 'content-type: application/json' \
     -d @samples/requests/chat_injection.json | python3 -m json.tool
   ```
   Highlight `"finish_reason": "content_filter"` and the `guardrails.stage: "input"`.

5. **Secret egress is caught on the way out (15s).** Run the check endpoint on model-style output.
   ```bash
   curl -s localhost:8000/guard/check \
     -H 'content-type: application/json' \
     -d @samples/requests/guard_check_secret.json | python3 -m json.tool
   ```
   Highlight `"action": "block"` with `private_key_header`.

6. **Close (5s).** "Deterministic, config-driven, OpenAI-compatible. Heuristic aid, human stays in the loop."

> Step 5's live proxy path (`chat_clean.json`) needs an upstream model (`ollama serve`). The check-endpoint steps work fully offline, so record those if no model is running.
