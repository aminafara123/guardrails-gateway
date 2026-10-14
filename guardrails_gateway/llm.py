"""Thin LLM client. The ONLY place the gateway talks to a model.

Calls an OpenAI-compatible /chat/completions endpoint. Defaults to a local
ollama server so it runs with no API key. Configured purely by env:

  LLM_BASE_URL  default http://127.0.0.1:11434/v1
  LLM_MODEL     default qwen3:30b-a3b-instruct-2507-q4_K_M
  LLM_API_KEY   default "ollama" (ollama ignores it; a hosted provider uses it)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx


class LLMError(RuntimeError):
    """Raised when the upstream model is unreachable or errors."""


def _config() -> tuple:
    return (
        os.getenv("LLM_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/"),
        os.getenv("LLM_MODEL", "qwen3:30b-a3b-instruct-2507-q4_K_M"),
        os.getenv("LLM_API_KEY", "ollama"),
    )


def chat(
    messages: List[Dict[str, Any]],
    model: Optional[str] = None,
    response_format: Optional[Dict[str, Any]] = None,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    """Forward a non-streaming chat completion and return the raw provider JSON."""
    base, default_model, key = _config()
    body: Dict[str, Any] = {
        "model": model or default_model,
        "messages": messages,
        "stream": False,
    }
    if response_format:
        body["response_format"] = response_format
    try:
        resp = httpx.post(
            f"{base}/chat/completions",
            json=body,
            headers={"Authorization": f"Bearer {key}"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:  # noqa: BLE001 - deliberately degrade, never crash the server
        raise LLMError(f"upstream LLM unreachable at {base}: {e}") from e
