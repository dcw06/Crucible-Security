"""Attested boundary for executing generated tests against immutable source."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import io
import os
import re
import secrets
import tarfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

import httpx

MAX_SOURCE_ARCHIVE_BYTES = 25 * 1024 * 1024


@dataclass(frozen=True)
class SourceSnapshot:
    repository: str
    commit_sha: str
    archive: bytes
    sha256: str


@dataclass(frozen=True)
class SandboxExecution:
    status: str
    junit_xml: bytes | None = None
    detail: str = ""
    verified: bool = False
    source_commit: str | None = None
    collected_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    requirement_results: dict[str, dict] = field(default_factory=dict)

    @property
    def pass_rate(self) -> float | None:
        if not self.verified or self.collected_tests <= 0:
            return None
        return self.passed_tests / self.collected_tests

    @property
    def tests_passed(self) -> bool:
        return (
            self.verified
            and self.failed_tests == 0
            and all(
                int(result.get("failed", 0)) == 0
                for result in self.requirement_results.values()
            )
        )


def snapshot_source_files(
    snapshot: SourceSnapshot,
    filenames: list[str],
) -> tuple[dict[str, str], list[str]]:
    """Read complete changed files from the immutable GitHub tarball in memory."""
    wanted = set(filenames)
    found: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(snapshot.archive), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.issym() or member.islnk():
                    continue
                parts = member.name.replace("\\", "/").split("/", 1)
                relative = parts[1] if len(parts) == 2 else parts[0]
                if relative not in wanted or member.size > 2 * 1024 * 1024:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    continue
                try:
                    found[relative] = data.decode("utf-8")
                except UnicodeDecodeError:
                    continue
    except (tarfile.TarError, OSError):
        return {}, sorted(wanted)
    return found, sorted(wanted - set(found))


def validate_sandbox_config() -> None:
    mode = os.environ.get("TEST_EXECUTION_MODE", "disabled").lower()
    if mode not in {"disabled", "remote"}:
        raise RuntimeError("TEST_EXECUTION_MODE must be 'disabled' or 'remote'")
    if mode == "remote":
        url = os.environ.get("TEST_SANDBOX_URL", "")
        token = os.environ.get("TEST_SANDBOX_TOKEN", "")
        attestation = os.environ.get("TEST_SANDBOX_ATTESTATION_SECRET", "")
        if not url.startswith("https://"):
            raise RuntimeError("Remote test sandbox requires an HTTPS TEST_SANDBOX_URL")
        if len(token) < 32 or len(attestation) < 32:
            raise RuntimeError("Remote sandbox credentials must contain at least 32 characters")


async def fetch_source_snapshot(commit_sha: str) -> SourceSnapshot | None:
    """Download the immutable GitHub archive without passing GitHub credentials onward."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        return None
    token = os.environ.get("GITHUB_TOKEN", "")
    owner = os.environ.get("GITHUB_OWNER", "")
    repo = os.environ.get("GITHUB_REPO", "")
    if not all((token, owner, repo)):
        return None
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{commit_sha}"
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
    except httpx.HTTPError:
        return None
    if response.status_code != 200 or len(response.content) > MAX_SOURCE_ARCHIVE_BYTES:
        return None
    archive = response.content
    return SourceSnapshot(
        repository=f"{owner}/{repo}",
        commit_sha=commit_sha,
        archive=archive,
        sha256=hashlib.sha256(archive).hexdigest(),
    )


def _attestation_body(data: dict) -> bytes:
    keys = (
        "job_id", "job_status", "pytest_exit_code", "collected_tests",
        "infrastructure_errors", "source_commit", "source_sha256",
        "isolation", "requirement_results", "junit_sha256",
        "request_nonce", "test_code_sha256",
    )
    return json.dumps(
        {key: data.get(key) for key in keys},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def _valid_attestation(data: dict) -> bool:
    provided = str(data.get("attestation", ""))
    secret = os.environ.get("TEST_SANDBOX_ATTESTATION_SECRET", "")
    expected = hmac.new(secret.encode(), _attestation_body(data), hashlib.sha256).hexdigest()
    return bool(secret) and hmac.compare_digest(provided, expected)


def _junit_test_count(root: ET.Element) -> int:
    if root.tag == "testsuite":
        return int(root.attrib.get("tests", "0"))
    return sum(int(suite.attrib.get("tests", "0")) for suite in root.findall("testsuite"))


def _junit_outcomes(root: ET.Element) -> tuple[int, int, int, int]:
    testcases = list(root.iter("testcase"))
    failed = sum(
        case.find("failure") is not None or case.find("error") is not None
        for case in testcases
    )
    skipped = sum(case.find("skipped") is not None for case in testcases)
    passed = len(testcases) - failed - skipped
    return len(testcases), passed, failed, skipped


async def execute_generated_tests(
    test_code: str,
    snapshot: SourceSnapshot | None = None,
    expected_requirement_ids: list[str] | None = None,
) -> SandboxExecution:
    """Submit tests plus a verified immutable source archive to the remote sandbox."""
    mode = os.environ.get("TEST_EXECUTION_MODE", "disabled").lower()
    if mode == "disabled":
        return SandboxExecution(
            "DISABLED",
            detail="Generated-test execution is disabled; no model output was executed.",
        )
    if snapshot is None:
        return SandboxExecution("FAILED", detail="Immutable source snapshot is unavailable.")
    try:
        validate_sandbox_config()
    except RuntimeError:
        return SandboxExecution("FAILED", detail="Sandbox configuration is invalid.")

    expected_ids = sorted(set(expected_requirement_ids or []))
    request_nonce = secrets.token_hex(32)
    test_code_sha256 = hashlib.sha256(test_code.encode()).hexdigest()
    url = os.environ["TEST_SANDBOX_URL"].rstrip("/") + "/v1/pytest"
    headers = {"Authorization": f"Bearer {os.environ['TEST_SANDBOX_TOKEN']}"}
    payload = {
        "test_code": test_code,
        "test_code_sha256": test_code_sha256,
        "request_nonce": request_nonce,
        "source": {
            "repository": snapshot.repository,
            "commit_sha": snapshot.commit_sha,
            "sha256": snapshot.sha256,
            "archive_base64": base64.b64encode(snapshot.archive).decode(),
            "mount": "read_only",
        },
        "expected_requirement_ids": expected_ids,
        "isolation": {
            "network": "disabled", "run_as_non_root": True,
            "read_only_source": True, "timeout_seconds": 120,
            "cpu_limit": 1, "memory_mb": 512, "pids_limit": 64, "disk_mb": 128,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=135) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError:
        return SandboxExecution("FAILED", detail="Remote sandbox request failed.")
    if response.status_code != 200:
        return SandboxExecution("FAILED", detail="Remote sandbox rejected the job.")

    try:
        data = response.json()
        if data["job_status"] != "COMPLETED":
            raise ValueError("job incomplete")
        if data["pytest_exit_code"] not in (0, 1):
            raise ValueError("invalid pytest exit")
        if int(data["infrastructure_errors"]) != 0:
            raise ValueError("infrastructure errors")
        if data["source_commit"] != snapshot.commit_sha:
            raise ValueError("commit mismatch")
        if data["source_sha256"] != snapshot.sha256:
            raise ValueError("archive mismatch")
        if data["request_nonce"] != request_nonce:
            raise ValueError("request nonce mismatch")
        if data["test_code_sha256"] != test_code_sha256:
            raise ValueError("test-code digest mismatch")
        required_isolation = payload["isolation"]
        if data["isolation"] != required_isolation:
            raise ValueError("isolation mismatch")
        if not _valid_attestation(data):
            raise ValueError("invalid attestation")

        xml = str(data["junit_xml"]).encode()
        if len(xml) > 10 * 1024 * 1024:
            raise ValueError("oversized response")
        if not hmac.compare_digest(
            str(data["junit_sha256"]),
            hashlib.sha256(xml).hexdigest(),
        ):
            raise ValueError("JUnit digest mismatch")
        if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
            raise ValueError("unsafe XML")
        root = ET.fromstring(xml)
        if root.tag not in {"testsuite", "testsuites"}:
            raise ValueError("invalid JUnit XML")
        collected = int(data["collected_tests"])
        junit_collected, passed, failed, skipped = _junit_outcomes(root)
        if (
            collected <= 0
            or _junit_test_count(root) != collected
            or junit_collected != collected
        ):
            raise ValueError("empty or inconsistent test collection")
        if (data["pytest_exit_code"] == 0 and failed != 0) or (
            data["pytest_exit_code"] == 1 and failed == 0
        ):
            raise ValueError("pytest exit code contradicts JUnit outcomes")
        if skipped:
            raise ValueError("skipped tests are not accepted")

        requirement_results = data["requirement_results"]
        if not isinstance(requirement_results, dict):
            raise ValueError("invalid requirement results")
        if set(requirement_results) != set(expected_ids):
            raise ValueError("requirement coverage mismatch")
        requirement_collected = 0
        requirement_passed = 0
        requirement_failed = 0
        for result in requirement_results.values():
            if (
                not isinstance(result, dict)
                or int(result.get("collected", 0)) <= 0
                or int(result.get("passed", 0)) < 0
                or int(result.get("failed", 0)) < 0
                or int(result["passed"]) + int(result["failed"]) != int(result["collected"])
            ):
                raise ValueError("invalid requirement result")
            requirement_collected += int(result["collected"])
            requirement_passed += int(result["passed"])
            requirement_failed += int(result["failed"])
        if (
            requirement_collected != junit_collected
            or requirement_passed != passed
            or requirement_failed != failed
        ):
            raise ValueError("requirement outcomes contradict JUnit outcomes")
    except ValueError as exc:
        return SandboxExecution(
            "FAILED", detail=f"Remote sandbox returned an invalid result: {exc}."
        )
    except (ET.ParseError, KeyError, TypeError):
        return SandboxExecution("FAILED", detail="Remote sandbox returned an invalid result.")

    return SandboxExecution(
        "SUCCESS", junit_xml=xml, verified=True,
        source_commit=snapshot.commit_sha, collected_tests=collected,
        passed_tests=passed, failed_tests=failed, skipped_tests=skipped,
        requirement_results=requirement_results,
    )
