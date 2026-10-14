#!/usr/bin/env bash
# One-command run: create venv if missing, install deps, start the gateway.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

exec .venv/bin/python -m guardrails_gateway.app
