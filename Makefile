PYTHON := .venv/bin/python

.PHONY: setup test test-root test-crucible build check web api

setup:
	$(PYTHON) -m pip install -r requirements-dev.txt

test: test-root test-crucible

test-root:
	$(PYTHON) -m pytest test_generated_code.py -q

test-crucible:
	PYTHONPATH=crucible $(PYTHON) -m pytest crucible/tests -q

build:
	npm run build --prefix mcp-server
	npm run compile --prefix vscode-extension

check:
	$(PYTHON) -m compileall -q -x '/(node_modules|\\.venv)/' .
	$(MAKE) test
	$(MAKE) build

web:
	$(PYTHON) -m streamlit run crucible/dashboard.py

api:
	$(PYTHON) -m uvicorn crucible.main:app --reload
