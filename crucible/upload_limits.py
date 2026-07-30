"""Authoritative resource limits for upload scanning."""

from __future__ import annotations

import os
from pathlib import Path

MIB = 1024 * 1024


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    if not raw.isdigit():
        raise RuntimeError(f"{name} must be a positive integer")
    value = int(raw)
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


MAX_ARCHIVE_UPLOAD_BYTES = _bounded_int(
    "MAX_ARCHIVE_UPLOAD_BYTES", 200 * MIB, MIB, 200 * MIB,
)
MAX_SOURCE_UPLOAD_BYTES = _bounded_int(
    "MAX_SOURCE_UPLOAD_BYTES", 200 * MIB, MIB, 200 * MIB,
)
MAX_UPLOAD_BYTES = max(MAX_ARCHIVE_UPLOAD_BYTES, MAX_SOURCE_UPLOAD_BYTES)
MAX_EXTRACTED_BYTES = _bounded_int(
    "MAX_EXTRACTED_BYTES", 500 * MIB, MAX_ARCHIVE_UPLOAD_BYTES, 500 * MIB,
)
MAX_SYNTAX_FILE_BYTES = _bounded_int(
    "MAX_SYNTAX_FILE_BYTES", 10 * MIB, MIB, 50 * MIB,
)
MAX_CLAUDE_FILE_BYTES = _bounded_int(
    "MAX_CLAUDE_FILE_BYTES", 5 * MIB, MIB, 25 * MIB,
)
SCANNER_SCRATCH_DIR = Path(
    os.environ.get("SCANNER_SCRATCH_DIR", "/tmp/crucible-scanner")
)


def validate_upload_runtime_config() -> None:
    """Reject deployment settings that cannot admit their advertised maximum."""
    quota = _bounded_int(
        "SCANNER_BYTE_QUOTA_BYTES", 400 * MIB, 1, 10 * 1024 * MIB,
    )
    if quota < MAX_UPLOAD_BYTES:
        raise RuntimeError(
            "SCANNER_BYTE_QUOTA_BYTES must be at least the largest upload limit"
        )
    concurrency = _bounded_int("SCANNER_MAX_CONCURRENT", 1, 1, 32)
    if MAX_UPLOAD_BYTES >= 200 * MIB and concurrency > 1:
        raise RuntimeError(
            "200 MB upload support requires SCANNER_MAX_CONCURRENT=1"
        )


def ensure_scratch_directory() -> Path:
    """Create the dedicated private scratch root used by scanner temp files."""
    SCANNER_SCRATCH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    SCANNER_SCRATCH_DIR.chmod(0o700)
    return SCANNER_SCRATCH_DIR
