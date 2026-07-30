"""
auth.py — HMAC webhook verification (no external dependencies)
=============================================================
Kept in its own module so unit tests can import it without
triggering the full pipeline/agents/anthropic import chain.
"""

import hashlib
import hmac
import os


def _enabled(name: str) -> bool:
    raw = os.environ.get(name, "false").strip().lower()
    if raw in {"1", "true", "yes"}:
        return True
    if raw in {"0", "false", "no", ""}:
        return False
    raise RuntimeError(f"{name} must be a boolean value")


def validate_webhook_config() -> None:
    """Reject unsafe webhook configuration before the server starts."""
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    allow_unsigned = _enabled("ALLOW_UNSIGNED_WEBHOOKS")
    environment = os.environ.get("APP_ENV", "production").lower()
    if secret:
        return
    if allow_unsigned and environment != "production":
        return
    if allow_unsigned:
        raise RuntimeError("Unsigned webhooks are forbidden in production")
    raise RuntimeError("GITHUB_WEBHOOK_SECRET is required")


def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """
    Verify GitHub webhook HMAC-SHA256 signature.

    Uses positional args to avoid Python version compatibility issues:
        hmac.new(key, msg, digestmod)  — NOT hmac.new(key, msg=..., digestmod=...)

    Unsigned requests are accepted only when ALLOW_UNSIGNED_WEBHOOKS=true and
    APP_ENV is explicitly non-production.
    """
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        return _enabled("ALLOW_UNSIGNED_WEBHOOKS") and (
            os.environ.get("APP_ENV", "production").lower() != "production"
        )

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode(),
        payload_body,       # positional — not msg=payload_body
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature_header)
