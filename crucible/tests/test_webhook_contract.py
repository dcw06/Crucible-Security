"""Webhook request-boundary regression tests."""

import asyncio
import hashlib
import hmac
import json

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import main


def _request(body: bytes, headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/webhook",
        "raw_path": b"/webhook",
        "query_string": b"",
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        "client": ("127.0.0.1", 1),
        "server": ("test", 443),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def test_declared_oversized_webhook_is_rejected_before_reading(monkeypatch):
    monkeypatch.setattr(main, "MAX_WEBHOOK_BODY_BYTES", 10)
    request = _request(b"{}", {"Content-Length": "11"})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.github_webhook(request))
    assert exc.value.status_code == 413


def test_actual_oversized_webhook_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "MAX_WEBHOOK_BODY_BYTES", 1)
    request = _request(b"{}", {})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.github_webhook(request))
    assert exc.value.status_code == 413


def test_valid_webhook_persists_before_ack_without_fetching(monkeypatch):
    secret = "test-webhook-secret"
    monkeypatch.setattr(main, "GITHUB_OWNER", "owner")
    monkeypatch.setattr(main, "GITHUB_REPO", "repo")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)
    monkeypatch.setattr(main, "_fetch_pr_files", lambda *_: pytest.fail("must run in worker"))
    admitted = []
    monkeypatch.setattr(
        main, "enqueue_job",
        lambda *args: admitted.append(args) or True,
    )
    payload = {
        "action": "opened",
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 9, "head": {"sha": "a" * 40}},
    }
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256,
    ).hexdigest()
    request = _request(body, {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery-9",
    })
    response = asyncio.run(main.github_webhook(request))
    assert response.status_code == 202
    assert admitted == [("delivery-9", 9, "a" * 40, "owner/repo")]


def test_lease_heartbeat_fails_cleanly_after_bounded_errors(monkeypatch):
    calls = []

    async def no_wait(_):
        return None

    monkeypatch.setattr(main.asyncio, "sleep", no_wait)
    monkeypatch.setattr(
        main, "renew_job",
        lambda *_: calls.append("attempt") or False,
    )
    asyncio.run(main._renew_lease("delivery-1"))
    assert calls == ["attempt", "attempt", "attempt"]


def test_production_requires_durable_database(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s" * 32)
    monkeypatch.delenv("ALLOW_UNSIGNED_WEBHOOKS", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(main, "GITHUB_TOKEN", "token")
    monkeypatch.setattr(main, "GITHUB_OWNER", "owner")
    monkeypatch.setattr(main, "GITHUB_REPO", "repo")
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        main.validate_app_config()
