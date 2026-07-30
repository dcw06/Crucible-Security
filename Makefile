PYTHON := .venv/bin/python
PYTHON_BOOTSTRAP ?= python3

.PHONY: setup test test-root test-crucible test-worker test-desktop-worker build build-workers quality check web api

setup:
	$(PYTHON_BOOTSTRAP) -m venv .venv
	$(PYTHON) -m pip install -r requirements-dev.txt
	npm ci --prefix mcp-server
	npm ci --prefix vscode-extension
	npm ci --prefix browser-worker

test: test-root test-crucible

test-root:
	$(PYTHON) -m pytest test_*.py -q

test-crucible:
	PYTHONPATH=crucible $(PYTHON) -m pytest crucible/tests -q

test-worker:
	npm run lint --prefix browser-worker
	npm test --prefix browser-worker

test-desktop-worker:
	$(PYTHON) -m pytest desktop-worker/test_worker.py -q

build:
	npm run build --prefix mcp-server
	npm run compile --prefix vscode-extension

test-typescript:
	npm run lint --prefix mcp-server
	npm test --prefix mcp-server
	npm run lint --prefix vscode-extension
	npm test --prefix vscode-extension

quality:
	cmp -s crucible/requirements.txt crucible/constraints.txt
	$(PYTHON) -m ruff check . --select E9,F63,F7,F82
	$(PYTHON) -m mypy --ignore-missing-imports code_pipeline.py research_pipeline.py
	$(PYTHON) -m pip_audit
	$(PYTHON) -m pip_audit -r desktop-worker/requirements.txt
	@if git grep -nE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9_-]{20,})' -- ':!*.example' ':!**/*.example'; then \
		echo "Potential committed secret detected"; exit 1; \
	fi

check: quality
	$(PYTHON) -m compileall -q -x '/(node_modules|\\.venv)/' .
	$(MAKE) test
	$(MAKE) test-worker
	$(MAKE) test-desktop-worker
	$(MAKE) build
	$(MAKE) test-typescript

build-workers:
	docker build -f browser-worker/Dockerfile -t crucible-browser-worker:test browser-worker
	docker build -f desktop-worker/Dockerfile.linux -t crucible-desktop-worker:test desktop-worker

web:
	APP_ENV=development ALLOW_UNAUTHENTICATED_SCANNER=true \
		$(PYTHON) crucible/scanner_preload.py
	APP_ENV=development ALLOW_UNAUTHENTICATED_SCANNER=true \
		$(PYTHON) -m streamlit run crucible/dashboard.py \
		--server.address 127.0.0.1

api:
	$(PYTHON) -m uvicorn crucible.main:app --reload
