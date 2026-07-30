"""Contracts for normalized targets and attested browser evidence."""

import hashlib
import hmac
import json

import browser_sandbox
from adapters import WebAppAdapter
from application_adapters import (
    ApplicationTarget,
    EvidenceStatus,
    TargetKind,
)


def _target_and_plan():
    target = ApplicationTarget(TargetKind.WEB, "https://example.com")
    plan = WebAppAdapter().generate_tests(target, [])
    return target, plan


def test_web_adapter_generates_bounded_cross_browser_baseline():
    target, plan = _target_and_plan()

    assert plan.allowed_hosts == ("example.com",)
    assert plan.browsers == ("chromium", "firefox", "webkit")
    assert {test.requirement_id for test in plan.tests} == {
        "WEB-BASELINE", "WEB-ATTACK-SURFACE", "WEB-ACCESSIBILITY",
        "WEB-PASSIVE-SECURITY",
    }
    assert all(not test.destructive for test in plan.tests)


def test_unmapped_requirement_becomes_review_required_not_invented_selector():
    target = ApplicationTarget(TargetKind.WEB, "https://example.com")
    plan = WebAppAdapter().generate_tests(
        target,
        [{"req_id": "REQ-LOGIN", "description": "Users can sign in safely"}],
    )

    generated = next(test for test in plan.tests if test.requirement_id == "REQ-LOGIN")
    assert generated.steps[0].action == "review_required"
    assert all(step.action != "assert_visible_text" for step in generated.steps)


def test_browser_execution_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("WEB_DYNAMIC_MODE", raising=False)
    target, plan = _target_and_plan()

    evidence = browser_sandbox.execute_browser_plan(target, plan)

    assert evidence.verified is False
    assert evidence.pass_rate is None


def test_browser_target_must_be_explicitly_allowlisted(monkeypatch):
    monkeypatch.setenv("WEB_DYNAMIC_MODE", "remote")
    monkeypatch.setenv("BROWSER_SANDBOX_URL", "https://sandbox.example")
    monkeypatch.setenv("BROWSER_SANDBOX_TOKEN", "t" * 32)
    monkeypatch.setenv("BROWSER_SANDBOX_ATTESTATION_SECRET", "s" * 32)
    monkeypatch.setenv("WEB_ALLOWED_HOSTS", "other.example")
    target, plan = _target_and_plan()

    evidence = browser_sandbox.execute_browser_plan(target, plan)

    assert evidence.verified is False
    assert "not explicitly authorized" in evidence.infrastructure_errors[0]


def test_request_bound_browser_evidence_is_accepted(monkeypatch):
    secret = "s" * 32
    nonce = "a" * 64
    target, plan = _target_and_plan()
    plan_payload = browser_sandbox._plan_payload(plan)
    plan_sha = hashlib.sha256(
        json.dumps(
            plan_payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()
    results = [
        {
            "test_id": test.test_id,
            "requirement_id": test.requirement_id,
            "status": "PASSED",
            "severity": "INFO",
            "confidence": 1.0,
            "detail": "",
            "duration_ms": 10,
            "artifacts": [],
            "console_errors": [],
            "network_failures": [],
        }
        for test in plan.tests
    ]
    junit = (
        f'<testsuite tests="{len(results)}">'
        + "".join(
            f'<testcase classname="{item["requirement_id"]}" '
            f'name="{item["test_id"]}"/>'
            for item in results
        )
        + "</testsuite>"
    )
    data = {
        "job_id": "browser-job-1",
        "job_status": "COMPLETED",
        "request_nonce": nonce,
        "target_url": target.locator,
        "plan_sha256": plan_sha,
        "junit_xml": junit,
        "junit_sha256": hashlib.sha256(junit.encode()).hexdigest(),
        "results": results,
        "evidence_sha256": hashlib.sha256(
            json.dumps(
                results, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode()
        ).hexdigest(),
        "isolation": browser_sandbox.REQUIRED_ISOLATION,
        "accessibility_findings": [],
        "passive_findings": [],
    }
    data["attestation"] = hmac.new(
        secret.encode(),
        browser_sandbox._attestation_body(data),
        hashlib.sha256,
    ).hexdigest()

    class Response:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return data

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setenv("WEB_DYNAMIC_MODE", "remote")
    monkeypatch.setenv("BROWSER_SANDBOX_URL", "https://sandbox.example")
    monkeypatch.setenv("BROWSER_SANDBOX_TOKEN", "t" * 32)
    monkeypatch.setenv("BROWSER_SANDBOX_ATTESTATION_SECRET", secret)
    monkeypatch.setenv("WEB_ALLOWED_HOSTS", "example.com")
    monkeypatch.setattr(browser_sandbox.secrets, "token_hex", lambda _size: nonce)
    monkeypatch.setattr(browser_sandbox.httpx, "Client", Client)

    evidence = browser_sandbox.execute_browser_plan(target, plan)

    assert evidence.verified is True
    assert evidence.pass_rate == 1.0
    assert all(result.status == EvidenceStatus.PASSED for result in evidence.results)


def test_tampered_browser_evidence_is_rejected(monkeypatch):
    target, plan = _target_and_plan()
    monkeypatch.setenv("WEB_DYNAMIC_MODE", "remote")
    monkeypatch.setenv("BROWSER_SANDBOX_URL", "https://sandbox.example")
    monkeypatch.setenv("BROWSER_SANDBOX_TOKEN", "t" * 32)
    monkeypatch.setenv("BROWSER_SANDBOX_ATTESTATION_SECRET", "s" * 32)
    monkeypatch.setenv("WEB_ALLOWED_HOSTS", "example.com")

    class Response:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return {"attestation": "invalid"}

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(browser_sandbox.httpx, "Client", Client)

    evidence = browser_sandbox.execute_browser_plan(target, plan)

    assert evidence.verified is False
