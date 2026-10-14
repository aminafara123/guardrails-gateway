.PHONY: install test run

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

test:
	.venv/bin/python -m pytest -q

run:
	.venv/bin/python -m guardrails_gateway.app
