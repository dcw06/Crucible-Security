"""Sanitization and deployed-response policy regression tests."""

from web_evidence import (
    TlsEvidence,
    WebFetchResult,
    cookie_evidence,
    evaluate_passive_policy,
    redact_url,
    sanitize_headers,
)


def test_web_evidence_does_not_retain_secrets():
    headers, truncated = sanitize_headers(
        [
            ("Authorization", "Bearer secret"),
            ("Set-Cookie", "session=secret; Secure; HttpOnly"),
            ("X-Content-Type-Options", "nosniff"),
        ]
    )
    cookies = cookie_evidence(
        ["session=secret; Secure; HttpOnly; SameSite=Lax; Path=/"]
    )

    assert truncated is False
    assert "authorization" not in headers
    assert "set-cookie" not in headers
    assert cookies[0].name == "session"
    assert cookies[0].secure is True
    assert cookies[0].httponly is True
    assert "secret" not in repr(cookies)
    assert redact_url("https://example.com/?token=secret&view=board") == (
        "https://example.com/?token=%5BREDACTED%5D&view=board"
    )


def test_passive_policy_finds_missing_headers_and_unsafe_session_cookie():
    fetch = WebFetchResult(
        body=b"<html></html>",
        requested_url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        headers={},
        cookies=cookie_evidence(["session=value; Path=/"]),
        redirects=(),
        resolved_ip="93.184.216.34",
        tls=TlsEvidence("example.com", True),
        address_pinned=True,
    )

    findings = evaluate_passive_policy(fetch)
    titles = {item["title"] for item in findings}

    assert "Missing Content Security Policy" in titles
    assert "Missing clickjacking defense" in titles
    assert "Cookie session is missing Secure" in titles
    assert "Session cookie session is missing HttpOnly" in titles
    assert all("session=value" not in item["evidence"] for item in findings)
