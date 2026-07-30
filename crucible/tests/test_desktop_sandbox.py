"""Contract tests for request-bound native worker evidence."""

import base64
import hashlib
import time

import desktop_sandbox
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scan_models import ScannerStatus


def _configure(monkeypatch, tmp_path, platform="Windows"):
    desktop_sandbox.USED_WORKER_INSTANCES.clear()
    prefix = {"Windows": "WINDOWS", "macOS": "MACOS", "Linux": "LINUX"}[platform]
    monkeypatch.setenv(f"DESKTOP_{prefix}_WORKER_URL", "https://worker.example")
    monkeypatch.setenv(f"DESKTOP_{prefix}_WORKER_TOKEN", "t" * 32)
    launcher_key = Ed25519PrivateKey.generate()
    worker_key = Ed25519PrivateKey.generate()
    public_path = tmp_path / "launcher-public.pem"
    public_path.write_bytes(launcher_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setenv(
        f"DESKTOP_{prefix}_LAUNCHER_PUBLIC_KEY_PATH", str(public_path)
    )
    return launcher_key, worker_key


def _isolation_fields(launcher_key, worker_key):
    now = time.time()
    receipt = {
        "launcher_id": "launcher-1",
        "sandbox_id": "sandbox-1",
        "platform": "Windows",
        "issued_at": now - 1,
        "expires_at": now + 300,
        "isolation": desktop_sandbox.REQUIRED_ISOLATION,
        "resource_limits": {
            "cpu_count": 2, "memory_mib": 2048, "disk_mib": 1024,
            "processes": 64, "timeout_seconds": 300,
        },
        "worker_instance_id": "worker-1",
        "max_jobs": 1,
        "worker_public_key": base64.b64encode(
            worker_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode(),
    }
    receipt["signature"] = base64.b64encode(
        launcher_key.sign(desktop_sandbox._launcher_receipt_body(receipt))
    ).decode()
    return {
        "isolation": desktop_sandbox.REQUIRED_ISOLATION,
        "isolation_receipt_sha256": hashlib.sha256(
            desktop_sandbox._stable_json(receipt)
        ).hexdigest(),
        "launcher_id": receipt["launcher_id"],
        "sandbox_id": receipt["sandbox_id"],
        "worker_instance_id": receipt["worker_instance_id"],
        "resource_limits": receipt["resource_limits"],
        "runtime_isolation": {
            "run_as_non_root": True,
            "artifact_read_only": True,
            "launcher_receipt_valid": True,
            "hard_timeout_supervised": True,
        },
        "launcher_receipt": receipt,
    }


def test_request_bound_native_evidence_is_accepted(monkeypatch, tmp_path):
    launcher_key, worker_key = _configure(monkeypatch, tmp_path)
    nonce = "a" * 64
    monkeypatch.setattr(desktop_sandbox.secrets, "token_hex", lambda _size: nonce)
    artifact = tmp_path / "Demo.exe"
    artifact.write_bytes(b"MZ artifact")

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _url, **kwargs):
            request = kwargs["json"]
            evidence = {
                "findings": [],
                "coverage": {
                    "complete": True,
                    "checks": {
                        name: True
                        for name in desktop_sandbox.REQUIRED_CHECKS[".exe"]
                    },
                },
                "diagnostics": [],
            }
            data = {
                "job_id": "native-job-1",
                "job_status": "COMPLETED",
                "request_nonce": nonce,
                "artifact_sha256": request["artifact"]["sha256"],
                "platform": "Windows",
                "policy_id": desktop_sandbox.POLICY_ID,
                "policy_sha256": request["policy_sha256"],
                "evidence_sha256": hashlib.sha256(
                    desktop_sandbox._stable_json(evidence)
                ).hexdigest(),
                "tool_versions": {"powershell": "7"},
                **_isolation_fields(launcher_key, worker_key),
                **evidence,
            }
            data["worker_signature"] = base64.b64encode(
                worker_key.sign(desktop_sandbox._attestation_body(data))
            ).decode()

            class Response:
                status_code = 200
                content = b"{}"

                @staticmethod
                def json():
                    return data

            return Response()

    monkeypatch.setattr(desktop_sandbox.httpx, "Client", Client)

    result = desktop_sandbox.inspect_native_artifact(artifact, "Windows")

    assert result.status == ScannerStatus.SUCCESS
    assert result.metadata["verified_attestation"] is True
    assert result.metadata["artifact_sha256"] == hashlib.sha256(
        artifact.read_bytes()
    ).hexdigest()


def test_incomplete_claimed_coverage_is_rejected(monkeypatch, tmp_path):
    launcher_key, worker_key = _configure(monkeypatch, tmp_path)
    artifact = tmp_path / "Demo.exe"
    artifact.write_bytes(b"MZ artifact")

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _url, **kwargs):
            request = kwargs["json"]
            evidence = {
                "findings": [],
                "coverage": {"complete": True, "checks": {"pe_header": True}},
                "diagnostics": [],
            }
            data = {
                "job_id": "native-job-1", "job_status": "COMPLETED",
                "request_nonce": request["request_nonce"],
                "artifact_sha256": request["artifact"]["sha256"],
                "platform": "Windows",
                "policy_id": desktop_sandbox.POLICY_ID,
                "policy_sha256": request["policy_sha256"],
                "evidence_sha256": hashlib.sha256(
                    desktop_sandbox._stable_json(evidence)
                ).hexdigest(),
                "tool_versions": {},
                **_isolation_fields(launcher_key, worker_key),
                **evidence,
            }
            data["worker_signature"] = base64.b64encode(
                worker_key.sign(desktop_sandbox._attestation_body(data))
            ).decode()

            class Response:
                status_code = 200
                content = b"{}"

                @staticmethod
                def json():
                    return data

            return Response()

    monkeypatch.setattr(desktop_sandbox.httpx, "Client", Client)

    result = desktop_sandbox.inspect_native_artifact(artifact, "Windows")

    assert result.status == ScannerStatus.FAILED


def test_native_evidence_bound_to_wrong_artifact_is_rejected(monkeypatch, tmp_path):
    launcher_key, worker_key = _configure(monkeypatch, tmp_path)
    artifact = tmp_path / "Demo.exe"
    artifact.write_bytes(b"MZ artifact")

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _url, **kwargs):
            request = kwargs["json"]
            data = {
                "job_id": "native-job-1", "job_status": "COMPLETED",
                "request_nonce": request["request_nonce"],
                "artifact_sha256": "0" * 64, "platform": "Windows",
                "policy_id": desktop_sandbox.POLICY_ID,
                "policy_sha256": request["policy_sha256"],
                "evidence_sha256": "0" * 64, "tool_versions": {},
                **_isolation_fields(launcher_key, worker_key),
                "findings": [], "coverage": {"complete": True}, "diagnostics": [],
            }
            data["worker_signature"] = base64.b64encode(
                worker_key.sign(desktop_sandbox._attestation_body(data))
            ).decode()

            class Response:
                status_code = 200
                content = b"{}"

                @staticmethod
                def json():
                    return data

            return Response()

    monkeypatch.setattr(desktop_sandbox.httpx, "Client", Client)

    result = desktop_sandbox.inspect_native_artifact(artifact, "Windows")

    assert result.status == ScannerStatus.FAILED
    assert "invalid evidence" in result.errors[0]


def test_native_worker_requires_https_and_long_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("DESKTOP_WINDOWS_WORKER_URL", "http://worker.example")
    artifact = tmp_path / "Demo.exe"
    artifact.write_bytes(b"MZ artifact")

    result = desktop_sandbox.inspect_native_artifact(artifact, "Windows")

    assert result.status == ScannerStatus.PARTIAL


def test_crucible_rejects_forged_launcher_receipt(monkeypatch, tmp_path):
    launcher_key, worker_key = _configure(monkeypatch, tmp_path)
    receipt = _isolation_fields(launcher_key, worker_key)["launcher_receipt"]
    receipt["sandbox_id"] = "forged-sandbox"

    with pytest.raises(InvalidSignature):
        desktop_sandbox._verify_launcher_receipt(
            receipt, launcher_key.public_key(), "Windows"
        )


def test_worker_instance_is_one_time():
    desktop_sandbox.USED_WORKER_INSTANCES.clear()
    desktop_sandbox._consume_worker_instance("worker-one")

    with pytest.raises(ValueError, match="replayed"):
        desktop_sandbox._consume_worker_instance("worker-one")
