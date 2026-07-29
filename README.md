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
├── crucible/              # Security scanning web app (Git submodule)
├── mcp-server/            # MCP interface to the Writer/Critic prototype
└── vscode-extension/      # VS Code interface to the Writer/Critic prototype
```

`crucible/` is intentionally maintained as its own repository and connected to
this workspace as a Git submodule. Clone the complete workspace with:

```bash
git clone --recurse-submodules <workspace-url>
```

For an existing clone:

```bash
git submodule update --init --recursive
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
make web           # Crucible Streamlit web application
make api           # Crucible FastAPI webhook API
```

The root prototypes require Anthropic credentials for live model calls.
Crucible has additional scanner and service configuration documented in
[`crucible/README.md`](crucible/README.md).

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
