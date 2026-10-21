# Dependency review — 2026-10-21

The MCP TypeScript SDK and affected transitive JavaScript packages were refreshed within their declared compatible ranges; the updated Node lock audits without findings. Streamlit was updated to 1.66.1 (allowing Pillow 13), and Semgrep to 1.182.0 (updating Click and PyJWT requirements).

## One scoped upstream advisory remains

Semgrep 1.182.0 pins Python `mcp==1.29.0`, which is affected by [GHSA-84m7-p3x7-pcfv](https://github.com/advisories/GHSA-84m7-p3x7-pcfv). Upstream describes unbounded session retention in a **stateful Streamable HTTP MCP server**. Patched SDK versions are 1.30.0 and 2.2.0; overriding Semgrep's exact dependency pin would create an unsupported environment.

This application invokes Semgrep's scanning CLI; its Python application and desktop worker do not import MCP or start a Python MCP HTTP server. The separate `mcp-server/` is a TypeScript service with its own updated SDK. Consequently, the affected Python HTTP serving path is outside the application's current execution path. This is a scoped applicability decision, not a claim that the installed SDK is patched.

`scripts/audit_dependencies.py` replaces the previous four advisory suppressions with this one identified exception. It checks the exact Semgrep/SDK pair and rejects application-side Python MCP imports before auditing. The desktop-worker audit has no exception. CI and `make quality` run the same checks.

Reassess this exception on any Semgrep/SDK change, Python MCP integration, or deployment that starts Semgrep's MCP serving mode. Remove it once upstream permits a patched SDK. Never expose the affected stateful serving mode under this exception.
