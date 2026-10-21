"""Audit production dependencies with one narrowly scoped CLI-only exception."""
from __future__ import annotations

import ast
from importlib.metadata import version
from pathlib import Path
import subprocess
import sys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    # Semgrep currently pins this SDK. The exception is invalid for another
    # dependency combination or if the application starts using Python MCP.
    if (version("semgrep"), version("mcp")) != ("1.182.0", "1.29.0"):
        raise RuntimeError("Reassess the Semgrep/MCP advisory before changing its pinned versions")
    for directory in ("crucible", "desktop-worker"):
        for path in (root / directory).rglob("*.py"):
            if path.name.startswith("test_"):
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                if any(name.split(".")[0] == "mcp" for name in modules):
                    raise RuntimeError(f"Python MCP usage invalidates the CLI-only exception: {path}")
    commands = [
        [sys.executable, "-m", "pip_audit", "-r", "crucible/requirements.txt",
         "--ignore-vuln", "GHSA-84m7-p3x7-pcfv"],
        [sys.executable, "-m", "pip_audit", "-r", "desktop-worker/requirements.txt"],
    ]
    for command in commands:
        result = subprocess.run(command, cwd=root, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
