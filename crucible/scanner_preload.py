"""Preload scanner-engine readiness before Streamlit accepts user sessions."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .upload_scanner import check_scanner_readiness
except ImportError:
    from upload_scanner import check_scanner_readiness


SNAPSHOT_PATH = Path(
    os.environ.get(
        "SCANNER_READINESS_SNAPSHOT",
        "/tmp/crucible_scanner_readiness.json",
    )
)


def preload_scanner_readiness(path: Path = SNAPSHOT_PATH) -> dict[str, dict[str, Any]]:
    """Probe scanner engines and atomically publish a startup snapshot."""
    readiness = check_scanner_readiness()
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "readiness": readiness,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return readiness


def load_preloaded_scanner_readiness(
    path: Path = SNAPSHOT_PATH,
) -> dict[str, dict[str, Any]] | None:
    """Load a validated startup snapshot, returning None when unavailable."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    readiness = payload.get("readiness") if isinstance(payload, dict) else None
    if not isinstance(readiness, dict) or not readiness:
        return None
    for name, state in readiness.items():
        if (
            not isinstance(name, str)
            or not isinstance(state, dict)
            or not isinstance(state.get("available"), bool)
            or not isinstance(state.get("version"), (str, type(None)))
            or not isinstance(state.get("error"), (str, type(None)))
        ):
            return None
        state["version"] = state.get("version") or ""
        state["error"] = state.get("error") or ""
    return readiness


def scanner_snapshot_generated_at(path: Path = SNAPSHOT_PATH) -> str | None:
    """Return the snapshot timestamp for display and staleness awareness."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    generated_at = payload.get("generated_at") if isinstance(payload, dict) else None
    return generated_at if isinstance(generated_at, str) else None


if __name__ == "__main__":
    result = preload_scanner_readiness()
    available = sum(state["available"] for state in result.values())
    print(f"[Startup] Scanner readiness preloaded: {available}/{len(result)} ready")
