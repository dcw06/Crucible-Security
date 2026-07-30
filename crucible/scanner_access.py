"""Authentication and bounded admission control for public upload scanning."""

from __future__ import annotations

import hmac
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

try:
    from .upload_limits import (
        MAX_UPLOAD_BYTES,
        validate_upload_runtime_config,
    )
except ImportError:
    from upload_limits import MAX_UPLOAD_BYTES, validate_upload_runtime_config


def _enabled(name: str) -> bool:
    raw = os.environ.get(name, "false").strip().lower()
    if raw in {"1", "true", "yes"}:
        return True
    if raw in {"0", "false", "no", ""}:
        return False
    raise RuntimeError(f"{name} must be a boolean value")


def scanner_auth_required() -> bool:
    environment = os.environ.get("APP_ENV", "production").lower()
    bypass = _enabled("ALLOW_UNAUTHENTICATED_SCANNER")
    return not (bypass and environment != "production")


def validate_scanner_access_config() -> None:
    token = os.environ.get("SCANNER_ACCESS_TOKEN", "")
    if scanner_auth_required() and len(token) < 32:
        raise RuntimeError("SCANNER_ACCESS_TOKEN must contain at least 32 characters")
    if (
        _enabled("ALLOW_UNAUTHENTICATED_SCANNER")
        and os.environ.get("APP_ENV", "production").lower() == "production"
    ):
        raise RuntimeError("Unauthenticated scanning is forbidden in production")
    replicas = int(os.environ.get("SCANNER_REPLICAS", "1"))
    if replicas != 1:
        raise RuntimeError(
            "Upload scanning must remain single-replica until shared quota storage is configured"
        )
    validate_upload_runtime_config()


def authenticate_scanner_token(candidate: str) -> bool:
    if not scanner_auth_required():
        return True
    expected = os.environ.get("SCANNER_ACCESS_TOKEN", "")
    return bool(expected) and hmac.compare_digest(candidate.encode(), expected.encode())


@dataclass(frozen=True)
class Admission:
    accepted: bool
    reason: str = ""


class ScanAdmissionController:
    def __init__(self) -> None:
        self.max_concurrent = max(1, int(os.environ.get("SCANNER_MAX_CONCURRENT", "1")))
        self.rate_limit = max(1, int(os.environ.get("SCANNER_RATE_LIMIT", "5")))
        self.window_seconds = max(60, int(os.environ.get("SCANNER_RATE_WINDOW_SECONDS", "3600")))
        self.byte_quota = max(
            1, int(os.environ.get("SCANNER_BYTE_QUOTA_BYTES", str(400 * 1024 * 1024)))
        )
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)
        self._events: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def acquire(self, client_id: str, upload_bytes: int) -> Admission:
        if upload_bytes < 0 or upload_bytes > MAX_UPLOAD_BYTES:
            return Admission(False, "Upload exceeds the configured maximum size.")
        now = time.monotonic()
        with self._lock:
            for identity in list(self._events):
                existing = self._events[identity]
                while existing and now - existing[0][0] >= self.window_seconds:
                    existing.popleft()
                if not existing:
                    del self._events[identity]
            events = self._events[client_id]
            if len(events) >= self.rate_limit:
                return Admission(False, "Scan rate limit reached. Try again later.")
            if sum(size for _, size in events) + upload_bytes > self.byte_quota:
                return Admission(False, "Upload quota reached. Try again later.")
            if not self._semaphore.acquire(blocking=False):
                return Admission(False, "Scanner capacity is full. Try again shortly.")
            events.append((now, upload_bytes))
        return Admission(True)

    def release(self) -> None:
        self._semaphore.release()


SCAN_ADMISSION = ScanAdmissionController()
