"""Native worker structural-parser and replay contract tests."""

import importlib.util
import base64
import json
import plistlib
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SPEC = importlib.util.spec_from_file_location(
    "desktop_worker", Path(__file__).with_name("worker.py")
)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(worker)


def _minimal_pe() -> bytes:
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    return bytes(data)


def test_pe_parser_validates_real_pe_offset_and_signature(tmp_path):
    artifact = tmp_path / "Demo.exe"
    artifact.write_bytes(_minimal_pe())

    findings, checks, _diagnostics = worker.inspect_pe(artifact)

    assert checks["dos_header"] is True
    assert checks["pe_header"] is True
    assert any(item["vulnerability_type"] == "UNSIGNED_BINARY" for item in findings)


def test_mz_only_file_is_not_a_valid_pe(tmp_path):
    artifact = tmp_path / "Spoof.exe"
    artifact.write_bytes(b"MZ" + b"\0" * 100)

    findings, checks, _diagnostics = worker.inspect_pe(artifact)

    assert checks["pe_header"] is False
    assert findings[0]["vulnerability_type"] == "INVALID_PE"


def test_msix_requires_manifest_and_signature(tmp_path):
    import zipfile

    artifact = tmp_path / "Demo.msix"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("payload.txt", "data")

    findings, checks, _diagnostics = worker.inspect_msix(artifact)

    assert checks["manifest"] is False
    assert checks["package_signature"] is True
    assert {item["vulnerability_type"] for item in findings} == {
        "INVALID_MSIX", "UNSIGNED_PACKAGE",
    }


def test_worker_rejects_replayed_nonce():
    worker.PLATFORM = "Linux"
    worker.NONCES.clear()
    raw = b"!<arch>\n"
    policy = {
        "policy_id": worker.POLICY_ID,
        "artifact_type": ".deb",
        "required_checks": sorted(worker.REQUIRED_CHECKS[".deb"]),
        "max_artifact_bytes": worker.MAX_ARTIFACT_BYTES,
        "max_findings": 1_000,
        "max_diagnostic_chars": worker.MAX_OUTPUT_CHARS,
        "isolation": worker.ISOLATION,
    }
    request = {
        "request_nonce": "a" * 64,
        "platform": "Linux",
        "artifact": {
            "name": "Demo.deb",
            "size_bytes": len(raw),
            "sha256": worker.digest(raw),
            "data_base64": base64.b64encode(raw).decode(),
        },
        "policy": policy,
        "policy_sha256": worker.digest(worker.stable_json(policy)),
    }

    worker.validate_request(request)

    import pytest
    with pytest.raises(ValueError, match="replayed"):
        worker.validate_request(request)


def test_empty_dmg_cannot_report_complete(monkeypatch, tmp_path):
    worker.PLATFORM = "macOS"
    artifact = tmp_path / "Demo.dmg"
    artifact.write_bytes(b"\0" * 512 + b"koly" + b"\0" * 508)
    monkeypatch.setattr(
        worker.shutil, "which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr(
        worker, "run_tool",
        lambda command, timeout=60: (True, "attached"),
    )

    findings, coverage, _tools, _diagnostics = worker.inspect_macos(artifact)

    assert coverage["complete"] is False
    assert coverage["checks"]["contained_applications"] is False
    assert any(
        item["vulnerability_type"] == "MISSING_APP_BUNDLE"
        for item in findings
    )


def test_launcher_signed_isolation_receipt_is_required(monkeypatch, tmp_path):
    worker.PLATFORM = "Linux"
    worker_key = Ed25519PrivateKey.generate()
    now = time.time()
    receipt = {
        "launcher_id": "launcher-1",
        "sandbox_id": "sandbox-1",
        "platform": "Linux",
        "issued_at": now - 1,
        "expires_at": now + 300,
        "isolation": worker.ISOLATION,
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
    private_key = Ed25519PrivateKey.generate()
    receipt["signature"] = base64.b64encode(
        private_key.sign(worker.isolation_receipt_body(receipt))
    ).decode()
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    path.chmod(0o444)
    public_key_path = tmp_path / "launcher-public.pem"
    public_key_path.write_bytes(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    public_key_path.chmod(0o444)
    monkeypatch.setenv("DESKTOP_ISOLATION_RECEIPT_PATH", str(path))
    monkeypatch.setenv(
        "DESKTOP_LAUNCHER_PUBLIC_KEY_PATH", str(public_key_path)
    )

    validated = worker.validate_isolation_receipt(worker_key)

    assert validated["launcher_id"] == "launcher-1"
    assert len(validated["receipt_sha256"]) == 64


def test_entitlements_are_parsed_and_risky_values_are_findings(
    monkeypatch, tmp_path,
):
    app = tmp_path / "Demo.app"
    executable = app / "Contents" / "MacOS" / "Demo"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"binary")
    executable.chmod(0o755)
    payload = plistlib.dumps({
        "com.apple.security.get-task-allow": True,
    })
    monkeypatch.setattr(worker.shutil, "which", lambda _name: "/usr/bin/codesign")
    monkeypatch.setattr(
        worker.subprocess, "run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"returncode": 0, "stdout": payload, "stderr": b""}
        )(),
    )

    complete, findings, _diagnostics = worker.inspect_entitlements(app)

    assert complete is True
    assert any(
        item["vulnerability_type"] == "RISKY_MACOS_ENTITLEMENT"
        for item in findings
    )


def test_absolute_deadline_terminates_inspection_process(monkeypatch, tmp_path):
    class Queue:
        @staticmethod
        def empty():
            return True

    class Process:
        pid = 123
        exitcode = None

        @staticmethod
        def start():
            return None

        @staticmethod
        def join(timeout=None):
            return None

        @staticmethod
        def is_alive():
            return True

    class Context:
        @staticmethod
        def Queue(maxsize=1):
            return Queue()

        @staticmethod
        def Process(**_kwargs):
            return Process()

    terminated = []
    monkeypatch.setattr(
        worker.multiprocessing, "get_context", lambda _mode: Context()
    )
    monkeypatch.setattr(
        worker, "_terminate_process_tree", lambda process: terminated.append(process.pid)
    )
    import pytest

    with pytest.raises(TimeoutError, match="hard deadline"):
        worker.inspect_with_deadline(tmp_path / "Demo.exe", 1)

    assert terminated == [123]
