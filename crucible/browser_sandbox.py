"""Attested client boundary for non-destructive browser testing."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import base64
import xml.etree.ElementTree as ET
from dataclasses import asdict
from urllib.parse import urlsplit

import httpx

try:
    from .application_adapters import (
        ApplicationTarget,
        EvidenceArtifact,
        EvidenceBundle,
        EvidenceStatus,
        NormalizedTestResult,
        TestPlan,
    )
except ImportError:
    from application_adapters import (
        ApplicationTarget,
        EvidenceArtifact,
        EvidenceBundle,
        EvidenceStatus,
        NormalizedTestResult,
        TestPlan,
    )


MAX_JUNIT_BYTES = 10 * 1024 * 1024
MAX_BROWSER_RESPONSE_BYTES = 30 * 1024 * 1024
MAX_RESULTS = 20
REQUIRED_ISOLATION = {
    "ephemeral": True,
    "run_as_non_root": True,
    "host_filesystem": "none",
    "credentials": "job_scoped",
    "destructive_actions": False,
}


def configured_allowed_hosts() -> set[str]:
    return {
        host.strip().lower().rstrip(".")
        for host in os.environ.get("WEB_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    }


def validate_browser_sandbox_config() -> None:
    mode = os.environ.get("WEB_DYNAMIC_MODE", "disabled").strip().lower()
    if mode not in {"disabled", "remote"}:
        raise RuntimeError("WEB_DYNAMIC_MODE must be 'disabled' or 'remote'")
    if mode == "disabled":
        return
    url = os.environ.get("BROWSER_SANDBOX_URL", "")
    token = os.environ.get("BROWSER_SANDBOX_TOKEN", "")
    secret = os.environ.get("BROWSER_SANDBOX_ATTESTATION_SECRET", "")
    if not url.startswith("https://"):
        raise RuntimeError("Browser sandbox requires an HTTPS URL")
    if len(token) < 32 or len(secret) < 32:
        raise RuntimeError("Browser sandbox credentials must contain at least 32 characters")
    if not configured_allowed_hosts():
        raise RuntimeError("WEB_ALLOWED_HOSTS must contain an authorized target host")


def _plan_payload(plan: TestPlan) -> dict:
    return asdict(plan)


def _attestation_body(payload: dict) -> bytes:
    keys = (
        "job_id", "job_status", "request_nonce", "target_url",
        "plan_sha256", "junit_sha256", "evidence_sha256", "isolation",
    )
    return json.dumps(
        {key: payload.get(key) for key in keys},
        sort_keys=True, ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _failed_bundle(target: ApplicationTarget, detail: str) -> EvidenceBundle:
    return EvidenceBundle(
        target=target,
        results=(),
        junit_xml=b"",
        verified=False,
        infrastructure_errors=(detail,),
    )


def execute_browser_plan(
    target: ApplicationTarget,
    plan: TestPlan,
) -> EvidenceBundle:
    """Submit a declarative plan and accept only request-bound attested evidence."""
    if os.environ.get("WEB_DYNAMIC_MODE", "disabled").lower() == "disabled":
        return _failed_bundle(target, "Browser execution is disabled.")
    try:
        validate_browser_sandbox_config()
    except RuntimeError:
        return _failed_bundle(target, "Browser sandbox configuration is invalid.")

    parsed = urlsplit(target.locator)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    allowed = configured_allowed_hosts()
    if parsed.scheme != "https" or hostname not in allowed:
        return _failed_bundle(target, "Target host is not explicitly authorized.")
    if set(plan.allowed_hosts) - allowed or hostname not in plan.allowed_hosts:
        return _failed_bundle(target, "Test plan exceeds the authorized host scope.")
    if any(test.destructive for test in plan.tests):
        return _failed_bundle(target, "Destructive browser actions are forbidden.")
    if not plan.tests or len(plan.tests) > MAX_RESULTS:
        return _failed_bundle(target, "Browser test plan size is invalid.")

    plan_payload = _plan_payload(plan)
    plan_sha256 = hashlib.sha256(
        json.dumps(
            plan_payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()
    request_nonce = secrets.token_hex(32)
    request = {
        "request_nonce": request_nonce,
        "target": {"url": target.locator, "allowed_hosts": list(plan.allowed_hosts)},
        "plan": plan_payload,
        "plan_sha256": plan_sha256,
        "isolation": REQUIRED_ISOLATION,
    }
    try:
        with httpx.Client(timeout=330) as client:
            response = client.post(
                os.environ["BROWSER_SANDBOX_URL"].rstrip("/") + "/v1/playwright",
                headers={
                    "Authorization": f"Bearer {os.environ['BROWSER_SANDBOX_TOKEN']}"
                },
                json=request,
            )
    except httpx.HTTPError:
        return _failed_bundle(target, "Browser sandbox request failed.")
    if response.status_code != 200:
        return _failed_bundle(target, "Browser sandbox rejected the job.")
    if len(response.content) > MAX_BROWSER_RESPONSE_BYTES:
        return _failed_bundle(target, "Browser sandbox response exceeded the evidence limit.")

    try:
        data = response.json()
        secret = os.environ["BROWSER_SANDBOX_ATTESTATION_SECRET"]
        expected = hmac.new(
            secret.encode(), _attestation_body(data), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(str(data["attestation"]), expected):
            raise ValueError("invalid attestation")
        if (
            data["job_status"] != "COMPLETED"
            or data["request_nonce"] != request_nonce
            or data["target_url"] != target.locator
            or data["plan_sha256"] != plan_sha256
            or data["isolation"] != REQUIRED_ISOLATION
        ):
            raise ValueError("request binding mismatch")

        junit = str(data["junit_xml"]).encode()
        if len(junit) > MAX_JUNIT_BYTES:
            raise ValueError("oversized JUnit")
        if hashlib.sha256(junit).hexdigest() != data["junit_sha256"]:
            raise ValueError("JUnit digest mismatch")
        if b"<!DOCTYPE" in junit.upper() or b"<!ENTITY" in junit.upper():
            raise ValueError("unsafe JUnit")
        root = ET.fromstring(junit)
        if root.tag not in {"testsuite", "testsuites"}:
            raise ValueError("invalid JUnit root")

        raw_results = data["results"]
        if not isinstance(raw_results, list) or len(raw_results) != len(plan.tests):
            raise ValueError("result count mismatch")
        evidence_sha256 = hashlib.sha256(
            json.dumps(
                raw_results, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode()
        ).hexdigest()
        if evidence_sha256 != data["evidence_sha256"]:
            raise ValueError("evidence digest mismatch")
        expected_tests = {(test.test_id, test.requirement_id) for test in plan.tests}
        actual_tests = {
            (str(item["test_id"]), str(item["requirement_id"]))
            for item in raw_results
        }
        if actual_tests != expected_tests:
            raise ValueError("test identity mismatch")

        results = tuple(
            NormalizedTestResult(
                test_id=str(item["test_id"]),
                requirement_id=str(item["requirement_id"]),
                status=EvidenceStatus(str(item["status"])),
                severity=str(item.get("severity", "INFO")),
                confidence=float(item.get("confidence", 1.0)),
                detail=str(item.get("detail", "")),
                duration_ms=int(item.get("duration_ms", 0)),
                artifacts=tuple(
                    _parse_artifact(artifact)
                    for artifact in item.get("artifacts", [])
                ),
                console_errors=tuple(map(str, item.get("console_errors", []))),
                network_failures=tuple(map(str, item.get("network_failures", []))),
            )
            for item in raw_results
        )
        return EvidenceBundle(
            target=target,
            results=results,
            junit_xml=junit,
            verified=True,
            sandbox_id=str(data["job_id"]),
            isolation=dict(data["isolation"]),
            accessibility_findings=tuple(data.get("accessibility_findings", [])),
            passive_findings=tuple(data.get("passive_findings", [])),
        )
    except (KeyError, TypeError, ValueError, ET.ParseError):
        return _failed_bundle(target, "Browser sandbox returned invalid evidence.")


def _parse_artifact(artifact: dict) -> EvidenceArtifact:
    encoded = artifact.get("data_base64")
    content = base64.b64decode(encoded, validate=True) if encoded else None
    size = int(artifact["size_bytes"])
    digest = str(artifact["sha256"])
    if content is not None and (
        len(content) != size
        or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), digest)
    ):
        raise ValueError("artifact digest mismatch")
    return EvidenceArtifact(
        kind=str(artifact["kind"]),
        name=str(artifact["name"]),
        sha256=digest,
        media_type=str(artifact["media_type"]),
        size_bytes=size,
        download_url=artifact.get("download_url"),
        content=content,
    )
