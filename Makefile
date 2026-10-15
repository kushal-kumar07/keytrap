# Uses a local virtualenv (.venv). Override the base interpreter with: make setup PYTHON=python3.12
PYTHON ?= $(shell command -v python3.13 || command -v python3.12 || command -v python3.11)
VENV   := .venv
BIN    := $(VENV)/bin

.PHONY: setup test test-fast scan lint clean

$(BIN)/python:
	@test -n "$(PYTHON)" || { echo "Python 3.11+ not found. Install it or pass PYTHON=/path/to/python"; exit 1; }
	$(PYTHON) -m venv $(VENV)

setup: $(BIN)/python
	$(BIN)/pip install -r requirements.txt

test: setup
	$(BIN)/python -m pytest tests/ -v --cov=keytrap

test-fast: setup
	$(BIN)/python -m pytest tests/ -v -x

# Usage: make scan TARGET=/path/to/repo   (extra flags: make scan TARGET=. ARGS="--safe-mode -v")
scan: setup
	@test -n "$(TARGET)" || { echo "Usage: make scan TARGET=<path-or-git-url> [ARGS=\"...\"]"; exit 1; }
	$(BIN)/python -m keytrap.cli scan $(TARGET) $(ARGS)

lint: setup
	$(BIN)/pip install -q ruff mypy
	$(BIN)/ruff check . && $(BIN)/mypy .

clean:
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
