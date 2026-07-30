"""Sanitized deployed-web evidence and deterministic passive policy checks."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from http.cookies import SimpleCookie
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_HEADER_VALUE_CHARS = 4_096
MAX_HEADER_METADATA_CHARS = 64_000
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}
SECRET_QUERY_MARKERS = {
    "access_token", "api_key", "apikey", "auth", "code", "key", "password",
    "secret", "session", "signature", "sig", "token",
}


@dataclass(frozen=True)
class CookieEvidence:
    name: str
    secure: bool
    httponly: bool
    samesite: str
    path: str
    domain: str
    max_age_present: bool
    expires_present: bool


@dataclass(frozen=True)
class RedirectEvidence:
    status_code: int
    requested_url: str
    location: str


@dataclass(frozen=True)
class TlsEvidence:
    hostname: str
    certificate_verified: bool
    protocol: str = ""
    cipher: str = ""
    certificate_expires_at: str = ""
    coverage_complete: bool = False


@dataclass(frozen=True)
class WebFetchResult:
    body: bytes
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, tuple[str, ...]]
    cookies: tuple[CookieEvidence, ...]
    redirects: tuple[RedirectEvidence, ...]
    resolved_ip: str
    tls: TlsEvidence
    metadata_truncated: bool = False
    address_pinned: bool = False

    def metadata(self) -> dict:
        return {
            "requested_url": redact_url(self.requested_url),
            "final_url": redact_url(self.final_url),
            "status_code": self.status_code,
            "headers": self.headers,
            "cookies": [asdict(cookie) for cookie in self.cookies],
            "redirects": [asdict(redirect) for redirect in self.redirects],
            "resolved_ip": self.resolved_ip,
            "tls": asdict(self.tls),
            "metadata_truncated": self.metadata_truncated,
            "address_pinned": self.address_pinned,
            "bytes_fetched": len(self.body),
            "scope": "delivered entry-page HTML and sanitized response metadata",
        }


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [
        (key, "[REDACTED]" if any(marker in key.lower() for marker in SECRET_QUERY_MARKERS) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def sanitize_headers(
    items: Iterable[tuple[str, str]],
) -> tuple[dict[str, tuple[str, ...]], bool]:
    collected: dict[str, list[str]] = {}
    total = 0
    truncated = False
    for raw_name, raw_value in items:
        name = raw_name.lower().strip()
        if name in SENSITIVE_HEADERS:
            continue
        value = raw_value.strip()
        if len(value) > MAX_HEADER_VALUE_CHARS:
            value = value[:MAX_HEADER_VALUE_CHARS]
            truncated = True
        projected = total + len(name) + len(value)
        if projected > MAX_HEADER_METADATA_CHARS:
            truncated = True
            continue
        total = projected
        collected.setdefault(name, []).append(value)
    return {key: tuple(values) for key, values in collected.items()}, truncated


def cookie_evidence(set_cookie_headers: Iterable[str]) -> tuple[CookieEvidence, ...]:
    evidence = []
    for header in set_cookie_headers:
        jar = SimpleCookie()
        try:
            jar.load(header)
        except Exception:
            continue
        for name, morsel in jar.items():
            evidence.append(
                CookieEvidence(
                    name=name[:256],
                    secure=bool(morsel["secure"]),
                    httponly=bool(morsel["httponly"]),
                    samesite=str(morsel["samesite"] or "").lower(),
                    path=str(morsel["path"] or ""),
                    domain=str(morsel["domain"] or ""),
                    max_age_present=bool(morsel["max-age"]),
                    expires_present=bool(morsel["expires"]),
                )
            )
    return tuple(evidence)


def _finding(
    title: str, severity: str, evidence: str, url: str, control: str
) -> dict:
    return {
        "title": title,
        "vulnerability_type": "PASSIVE_WEB_SECURITY",
        "severity": severity,
        "confidence": 1.0,
        "evidence": evidence,
        "file_path": None,
        "line_number": None,
        "product_control_ids": [control],
        "cwe_ids": [],
        "source": "web_passive",
        "mapped": True,
        "status": "FINDING",
        "recommendation": f"Apply the missing or unsafe policy to {redact_url(url)}.",
    }


def evaluate_passive_policy(fetch: WebFetchResult) -> list[dict]:
    """Evaluate controls that can be established from sanitized entry response data."""
    headers = fetch.headers
    url = fetch.final_url
    findings: list[dict] = []
    csp = " ".join(headers.get("content-security-policy", ())).lower()
    xfo = " ".join(headers.get("x-frame-options", ())).lower()
    checks = [
        ("strict-transport-security", "Missing HSTS", "MEDIUM", "WEB-004"),
        ("x-content-type-options", "Missing X-Content-Type-Options", "LOW", "WEB-004"),
        ("referrer-policy", "Missing Referrer-Policy", "LOW", "WEB-004"),
        ("permissions-policy", "Missing Permissions-Policy", "LOW", "WEB-004"),
    ]
    if not csp:
        findings.append(_finding("Missing Content Security Policy", "MEDIUM", f"CSP is absent from {redact_url(url)}", url, "WEB-004"))
    elif "'unsafe-eval'" in csp:
        findings.append(_finding("CSP permits unsafe-eval", "HIGH", "script-src permits dynamic code evaluation", url, "WEB-004"))
    elif "'unsafe-inline'" in csp:
        findings.append(_finding("CSP permits unsafe-inline scripts or styles", "MEDIUM", "CSP contains unsafe-inline and should use nonces or hashes", url, "WEB-004"))
    if "frame-ancestors" not in csp and xfo not in {"deny", "sameorigin"}:
        findings.append(_finding("Missing clickjacking defense", "MEDIUM", "Neither CSP frame-ancestors nor a valid X-Frame-Options fallback is present", url, "WEB-003"))
    for header, title, severity, control in checks:
        if not headers.get(header):
            findings.append(_finding(title, severity, f"{header} is absent from {redact_url(url)}", url, control))
    hsts = " ".join(headers.get("strict-transport-security", ())).lower()
    if hsts:
        try:
            max_age = next(
                int(part.split("=", 1)[1])
                for part in (item.strip() for item in hsts.split(";"))
                if part.startswith("max-age=")
            )
        except (StopIteration, ValueError):
            max_age = 0
        if max_age < 15_552_000:
            findings.append(_finding("HSTS max-age is too short", "MEDIUM", f"Observed max-age={max_age}", url, "WEB-004"))
    allow_origin = " ".join(headers.get("access-control-allow-origin", ())).strip()
    allow_credentials = " ".join(
        headers.get("access-control-allow-credentials", ())
    ).lower()
    if allow_origin == "*" and allow_credentials == "true":
        findings.append(_finding("Credentialed wildcard CORS policy", "HIGH", "Access-Control-Allow-Origin is * while credentials are enabled", url, "API-005"))
    for header in (
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "access-control-allow-origin",
    ):
        values = headers.get(header, ())
        if len(set(values)) > 1:
            findings.append(_finding(f"Conflicting {header} headers", "MEDIUM", f"{len(values)} differing values were observed", url, "WEB-004"))
    for cookie in fetch.cookies:
        session_like = any(marker in cookie.name.lower() for marker in ("session", "auth", "token", "sid"))
        if not cookie.secure:
            findings.append(_finding(f"Cookie {cookie.name} is missing Secure", "HIGH" if session_like else "MEDIUM", "Cookie attributes were inspected without retaining its value", url, "WEB-005"))
        if session_like and not cookie.httponly:
            findings.append(_finding(f"Session cookie {cookie.name} is missing HttpOnly", "HIGH", "Cookie attributes were inspected without retaining its value", url, "WEB-005"))
        if cookie.samesite not in {"lax", "strict"}:
            findings.append(_finding(f"Cookie {cookie.name} has weak SameSite policy", "MEDIUM", f"Observed SameSite={cookie.samesite or 'unset'}", url, "WEB-005"))
        if cookie.name.startswith("__Host-") and (not cookie.secure or cookie.domain or cookie.path != "/"):
            findings.append(_finding(f"Cookie {cookie.name} violates __Host- prefix rules", "HIGH", "A __Host- cookie must be Secure, host-only, and Path=/", url, "WEB-005"))
        if cookie.name.startswith("__Secure-") and not cookie.secure:
            findings.append(_finding(f"Cookie {cookie.name} violates __Secure- prefix rules", "HIGH", "A __Secure- cookie must be Secure", url, "WEB-005"))
        if cookie.domain.startswith("."):
            findings.append(_finding(f"Cookie {cookie.name} has broad subdomain scope", "LOW", f"Observed Domain={cookie.domain}", url, "WEB-005"))
    if fetch.metadata_truncated:
        findings.append(_finding("Response security metadata was truncated", "INFO", "Passive response coverage is partial because metadata limits were reached", url, "WEB-004"))
    if not fetch.address_pinned:
        findings.append(_finding("Web fetch address was not pinned", "INFO", "DNS was validated but this local fetch path does not provide gateway-attested address pinning", url, "INFRA-002"))
    return findings
