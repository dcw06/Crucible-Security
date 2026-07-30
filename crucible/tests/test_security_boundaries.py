"""Regression tests for execution and upload-service trust boundaries."""

import asyncio
import hashlib
import hmac
import inspect

import pytest
import test_sandbox

from scanner_access import (
    ScanAdmissionController,
    authenticate_scanner_token,
    scanner_auth_required,
    validate_scanner_access_config,
)
from test_sandbox import execute_generated_tests, validate_sandbox_config
from test_sandbox import (
    SandboxExecution,
    SourceSnapshot,
    _attestation_body,
    _junit_outcomes,
    _junit_test_count,
)


def test_generated_code_execution_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("TEST_EXECUTION_MODE", raising=False)
    result = asyncio.run(execute_generated_tests("raise RuntimeError('must not run')"))
    assert result.status == "DISABLED"
    assert result.junit_xml is None


def test_pipeline_contains_no_local_generated_test_execution():
    import pipeline

    source = inspect.getsource(pipeline)
    assert "create_subprocess_exec" not in source
    assert "execute_generated_tests" in source


def test_remote_sandbox_requires_https_and_token(monkeypatch):
    monkeypatch.setenv("TEST_EXECUTION_MODE", "remote")
    monkeypatch.setenv("TEST_SANDBOX_URL", "http://unsafe.example")
    monkeypatch.delenv("TEST_SANDBOX_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        validate_sandbox_config()


def test_empty_junit_suite_has_zero_collected_tests():
    import xml.etree.ElementTree as ET

    root = ET.fromstring('<testsuite tests="0"></testsuite>')
    assert _junit_test_count(root) == 0


def test_junit_failures_determine_authoritative_pass_rate():
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        '<testsuite tests="2"><testcase name="ok"/>'
        '<testcase name="bad"><failure/></testcase></testsuite>'
    )
    assert _junit_outcomes(root) == (2, 1, 1, 0)
    execution = SandboxExecution(
        "SUCCESS", verified=True, collected_tests=2,
        passed_tests=1, failed_tests=1,
    )
    assert execution.pass_rate == 0.5
    assert execution.tests_passed is False


def _signed_sandbox_response(
    monkeypatch, *, junit_xml, requirement_results,
    test_code="def test_ok(): pass", request_nonce="a" * 64,
):
    secret = "a" * 32
    isolation = {
        "network": "disabled", "run_as_non_root": True,
        "read_only_source": True, "timeout_seconds": 120,
        "cpu_limit": 1, "memory_mb": 512, "pids_limit": 64, "disk_mb": 128,
    }
    data = {
        "job_id": "job-1",
        "job_status": "COMPLETED",
        "pytest_exit_code": 0,
        "collected_tests": 1,
        "infrastructure_errors": 0,
        "source_commit": "1" * 40,
        "source_sha256": hashlib.sha256(b"archive").hexdigest(),
        "isolation": isolation,
        "requirement_results": requirement_results,
        "junit_xml": junit_xml,
        "junit_sha256": hashlib.sha256(junit_xml.encode()).hexdigest(),
        "test_code_sha256": hashlib.sha256(test_code.encode()).hexdigest(),
        "request_nonce": request_nonce,
    }
    data["attestation"] = hmac.new(
        secret.encode(), _attestation_body(data), hashlib.sha256,
    ).hexdigest()

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return data

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setenv("TEST_EXECUTION_MODE", "remote")
    monkeypatch.setenv("TEST_SANDBOX_URL", "https://sandbox.example")
    monkeypatch.setenv("TEST_SANDBOX_TOKEN", "t" * 32)
    monkeypatch.setenv("TEST_SANDBOX_ATTESTATION_SECRET", secret)
    monkeypatch.setattr(test_sandbox.httpx, "AsyncClient", Client)
    monkeypatch.setattr(test_sandbox.secrets, "token_hex", lambda _size: request_nonce)
    snapshot = SourceSnapshot(
        "owner/repo", "1" * 40, b"archive", hashlib.sha256(b"archive").hexdigest(),
    )
    return data, snapshot


def test_signed_requirement_results_must_match_junit(monkeypatch):
    data, snapshot = _signed_sandbox_response(
        monkeypatch,
        junit_xml='<testsuite tests="1"><testcase name="ok"/></testsuite>',
        requirement_results={"REQ-1": {"collected": 1, "passed": 0, "failed": 1}},
    )
    result = asyncio.run(
        execute_generated_tests(
            "def test_ok(): pass", snapshot, expected_requirement_ids=["REQ-1"],
        )
    )
    assert data["attestation"]
    assert result.status == "FAILED"
    assert result.verified is False


def test_matching_signed_junit_and_requirement_results_are_accepted(monkeypatch):
    _data, snapshot = _signed_sandbox_response(
        monkeypatch,
        junit_xml='<testsuite tests="1"><testcase name="ok"/></testsuite>',
        requirement_results={"REQ-1": {"collected": 1, "passed": 1, "failed": 0}},
    )
    result = asyncio.run(
        execute_generated_tests(
            "def test_ok(): pass", snapshot, expected_requirement_ids=["REQ-1"],
        )
    )
    assert result.status == "SUCCESS"
    assert result.verified is True
    assert result.tests_passed is True
    assert result.pass_rate == 1.0


def test_junit_digest_is_attested_and_verified(monkeypatch):
    data, snapshot = _signed_sandbox_response(
        monkeypatch,
        junit_xml='<testsuite tests="1"><testcase name="ok"/></testsuite>',
        requirement_results={"REQ-1": {"collected": 1, "passed": 1, "failed": 0}},
    )
    data["junit_xml"] = (
        '<testsuite tests="1"><testcase name="bad"><failure/></testcase></testsuite>'
    )
    result = asyncio.run(
        execute_generated_tests(
            "def test_ok(): pass", snapshot, expected_requirement_ids=["REQ-1"],
        )
    )
    assert result.status == "FAILED"
    assert result.verified is False


def test_response_for_one_test_suite_cannot_satisfy_another(monkeypatch):
    _data, snapshot = _signed_sandbox_response(
        monkeypatch,
        junit_xml='<testsuite tests="1"><testcase name="ok"/></testsuite>',
        requirement_results={"REQ-1": {"collected": 1, "passed": 1, "failed": 0}},
        test_code="def test_suite_a(): pass",
        request_nonce="a" * 64,
    )
    monkeypatch.setattr(test_sandbox.secrets, "token_hex", lambda _size: "b" * 64)
    result = asyncio.run(
        execute_generated_tests(
            "def test_suite_b(): pass",
            snapshot,
            expected_requirement_ids=["REQ-1"],
        )
    )
    assert result.status == "FAILED"
    assert result.verified is False


def test_skipped_tests_are_explicitly_rejected(monkeypatch):
    _data, snapshot = _signed_sandbox_response(
        monkeypatch,
        junit_xml=(
            '<testsuite tests="1"><testcase name="skip">'
            '<skipped/></testcase></testsuite>'
        ),
        requirement_results={"REQ-1": {"collected": 1, "passed": 0, "failed": 0}},
    )
    result = asyncio.run(
        execute_generated_tests(
            "def test_ok(): pass", snapshot, expected_requirement_ids=["REQ-1"],
        )
    )
    assert result.status == "FAILED"
    assert "skipped tests are not accepted" in result.detail


def test_requirement_failure_independently_blocks_execution():
    execution = SandboxExecution(
        "SUCCESS", verified=True, collected_tests=1, passed_tests=1,
        requirement_results={
            "REQ-1": {"collected": 1, "passed": 0, "failed": 1},
        },
    )
    assert execution.tests_passed is False


def test_scanner_requires_authentication_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ALLOW_UNAUTHENTICATED_SCANNER", raising=False)
    monkeypatch.delenv("SCANNER_ACCESS_TOKEN", raising=False)
    assert scanner_auth_required() is True
    with pytest.raises(RuntimeError):
        validate_scanner_access_config()


def test_scanner_token_uses_explicit_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SCANNER_ACCESS_TOKEN", "correct-horse-battery-staple")
    assert authenticate_scanner_token("wrong") is False
    assert authenticate_scanner_token("correct-horse-battery-staple") is True


def test_development_auth_bypass_must_be_explicit(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_SCANNER", "true")
    monkeypatch.delenv("SCANNER_ACCESS_TOKEN", raising=False)
    assert scanner_auth_required() is False
    validate_scanner_access_config()


def test_scan_rate_limit_and_byte_quota(monkeypatch):
    monkeypatch.setenv("SCANNER_MAX_CONCURRENT", "1")
    monkeypatch.setenv("SCANNER_RATE_LIMIT", "1")
    monkeypatch.setenv("SCANNER_RATE_WINDOW_SECONDS", "3600")
    monkeypatch.setenv("SCANNER_BYTE_QUOTA_BYTES", "10")
    controller = ScanAdmissionController()
    first = controller.acquire("client", 6)
    assert first.accepted is True
    controller.release()
    second = controller.acquire("client", 1)
    assert second.accepted is False


def test_scan_concurrency_limit(monkeypatch):
    monkeypatch.setenv("SCANNER_MAX_CONCURRENT", "1")
    monkeypatch.setenv("SCANNER_RATE_LIMIT", "5")
    controller = ScanAdmissionController()
    assert controller.acquire("one", 1).accepted is True
    assert controller.acquire("two", 1).accepted is False
    controller.release()
