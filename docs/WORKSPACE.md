> Detailed development and operations reference. Start with the [project overview](../README.md).

# Multi-Agent Workspace

This workspace collects a set of related multi-agent experiments and the
production-style Crucible application.

## Repository layout

```text
.
├── code_pipeline.py       # Original Python Writer/Critic prototype
├── research_pipeline.py   # Parallel research-agent prototype
├── generated_code.py      # Fixture produced by the Python prototype
├── test_generated_code.py # Root prototype regression suite
├── crucible/              # Security scanning web app (tracked directory)
├── browser-worker/        # Separate Playwright/axe execution boundary
├── desktop-worker/        # Attested native package inspection boundary
├── mcp-server/            # MCP interface to the Writer/Critic prototype
└── vscode-extension/      # VS Code interface to the Writer/Critic prototype
```

`crucible/` is an ordinary tracked directory in this workspace. Clone it normally:

```bash
git clone https://github.com/dcw06/Crucible-Updated-7-30-.git
cd Crucible-Updated-7-30-
```

## Development environment

Use one virtual environment at the workspace root:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements-dev.txt
```

Do not create or commit a second environment inside `crucible/`.

Useful commands:

```bash
make test          # Root and Crucible Python tests
make build         # MCP server and VS Code extension TypeScript builds
make check         # Python compilation, tests, and TypeScript builds
make test-worker   # Browser-worker policy contract tests
make test-desktop-worker # Native worker parser/contract tests
make web           # Local-only Crucible UI on 127.0.0.1
make api           # Crucible FastAPI webhook API
```

The root prototypes require Anthropic credentials for live model calls.
`research_pipeline.py` also requires `BRAVE_SEARCH_API_KEY`; it fails closed
when live search is unavailable and no longer produces simulated research.
Crucible has additional scanner and service configuration documented in
[`crucible/README.md`](../crucible/README.md).

`make web` explicitly uses the development-only unauthenticated scanner profile
and binds Streamlit to `127.0.0.1`. Production and Docker launches remain
fail-closed and require a `SCANNER_ACCESS_TOKEN` of at least 32 characters.

## Artifact policy

PDF design documents are small enough to remain workspace documentation.
Demo recordings (`*.mp4`, `*.mov`, and `*.m4v`) are intentionally local-only
and ignored by Git because they currently total more than 200 MB. Publish those
through release storage or an external media service if they need distribution.

Generated JavaScript, packaged VSIX files, dependency directories, virtual
environments, caches, SQLite state, and local secrets are also excluded.

## Component status

- Root Python files are historical prototypes and test fixtures.
- `crucible/` is the current web application and security-scanning system.
- `mcp-server/` and `vscode-extension/` expose the earlier Writer/Critic loop
  through MCP and VS Code respectively.
