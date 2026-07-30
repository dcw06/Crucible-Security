"""Attested client boundary for native desktop artifact inspection."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from .scan_models import ScannerResult, ScannerStatus
except ImportError:
    from scan_models import ScannerResult, ScannerStatus


MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 1_000
MAX_DIAGNOSTIC_CHARS = 4_096
POLICY_ID = "crucible-native-static-v2"
REQUIRED_ISOLATION = {
    "ephemeral": True,
    "run_as_non_root": True,
    "host_filesystem": "none",
    "network": "disabled",
    "artifact_mount": "read_only",
    "credentials": "none",
    "cpu_limit": True,
    "memory_limit": True,
    "pid_limit": True,
    "disk_limit": True,
    "hard_timeout": True,
}
USED_WORKER_INSTANCES: set[str] = set()
USED_WORKER_INSTANCES_LOCK = threading.Lock()

REQUIRED_CHECKS = {
    ".exe": frozenset({
        "dos_header", "pe_header", "sections", "imports", "resources",
        "authenticode",
    }),
    ".msi": frozenset({
        "ole_container", "tables", "embedded_cabs", "custom_actions",
        "authenticode",
    }),
    ".msix": frozenset({
        "zip_integrity", "manifest", "capabilities", "package_signature",
    }),
    ".dmg": frozenset({
        "udif_trailer", "partition_metadata", "contained_applications",
        "nested_code_signatures", "gatekeeper", "notarization_ticket",
        "macho_load_commands", "entitlements",
    }),
    ".pkg": frozenset({
        "xar_container", "payload_inventory", "bom_inventory",
        "installer_scripts", "package_signature", "gatekeeper",
        "notarization_ticket",
    }),
    ".app.zip": frozenset({
        "bundle_structure", "nested_code_signatures", "gatekeeper",
        "notarization_ticket", "macho_load_commands", "entitlements",
    }),
    ".deb": frozenset({
        "ar_container", "control_metadata", "maintainer_scripts",
        "file_inventory", "provenance",
    }),
    ".rpm": frozenset({
        "rpm_header", "metadata", "file_inventory", "installer_scripts",
        "signature",
    }),
    ".snap": frozenset({
        "filesystem_marker", "filesystem_inventory", "manifest",
        "confinement_or_runtime", "signature",
    }),
    ".appimage": frozenset({
        "filesystem_marker", "filesystem_inventory", "manifest",
        "confinement_or_runtime", "signature",
    }),
}


def _artifact_type(name: str) -> str | None:
    lowered = name.lower()
    if lowered.endswith(".app.zip"):
        return ".app.zip"
    suffix = Path(lowered).suffix
    return suffix if suffix in REQUIRED_CHECKS else None


def _stable_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode()


def _attestation_body(payload: dict[str, Any]) -> bytes:
    keys = (
        "job_id", "job_status", "request_nonce", "artifact_sha256",
        "platform", "policy_id", "policy_sha256", "evidence_sha256",
        "tool_versions", "isolation", "isolation_receipt_sha256",
        "launcher_id", "sandbox_id", "resource_limits", "runtime_isolation",
        "worker_instance_id",
    )
    return _stable_json({key: payload.get(key) for key in keys})


def _worker_environment(
    platform: str,
) -> tuple[str, str, Ed25519PublicKey] | None:
    prefix = {
        "Windows": "WINDOWS",
        "macOS": "MACOS",
        "Linux": "LINUX",
    }.get(platform)
    if not prefix:
        return None
    url = os.environ.get(f"DESKTOP_{prefix}_WORKER_URL", "")
    token = os.environ.get(f"DESKTOP_{prefix}_WORKER_TOKEN", "")
    launcher_key_path = Path(
        os.environ.get(f"DESKTOP_{prefix}_LAUNCHER_PUBLIC_KEY_PATH", "")
    )
    if (
        not url.startswith("https://")
        or len(token) < 32
        or not launcher_key_path.is_file()
    ):
        return None
    try:
        launcher_key = serialization.load_pem_public_key(
            launcher_key_path.read_bytes()
        )
    except (OSError, TypeError, ValueError):
        return None
    if not isinstance(launcher_key, Ed25519PublicKey):
        return None
    return url, token, launcher_key


def _launcher_receipt_body(receipt: dict[str, Any]) -> bytes:
    return _stable_json({
        key: receipt.get(key) for key in (
            "launcher_id", "sandbox_id", "platform", "issued_at", "expires_at",
            "isolation", "resource_limits", "worker_instance_id",
            "worker_public_key", "max_jobs",
        )
    })


def _verify_launcher_receipt(
    receipt: Any,
    launcher_key: Ed25519PublicKey,
    platform: str,
) -> tuple[dict[str, Any], Ed25519PublicKey]:
    if not isinstance(receipt, dict):
        raise ValueError("missing launcher receipt")
    launcher_key.verify(
        base64.b64decode(receipt["signature"], validate=True),
        _launcher_receipt_body(receipt),
    )
    now = time.time()
    if (
        receipt["platform"] != platform
        or receipt["isolation"] != REQUIRED_ISOLATION
        or not isinstance(receipt["launcher_id"], str)
        or not receipt["launcher_id"]
        or not isinstance(receipt["sandbox_id"], str)
        or not receipt["sandbox_id"]
        or not isinstance(receipt["worker_instance_id"], str)
        or not receipt["worker_instance_id"]
        or receipt["max_jobs"] != 1
        or not float(receipt["issued_at"]) <= now <= float(receipt["expires_at"])
        or float(receipt["expires_at"]) - float(receipt["issued_at"]) > 3600
    ):
        raise ValueError("invalid launcher receipt")
    raw_worker_key = base64.b64decode(
        receipt["worker_public_key"], validate=True
    )
    if len(raw_worker_key) != 32:
        raise ValueError("invalid worker public key")
    return receipt, Ed25519PublicKey.from_public_bytes(raw_worker_key)


def _consume_worker_instance(worker_instance_id: str) -> None:
    with USED_WORKER_INSTANCES_LOCK:
        if worker_instance_id in USED_WORKER_INSTANCES:
            raise ValueError("replayed worker instance")
        USED_WORKER_INSTANCES.add(worker_instance_id)


def configured_desktop_workers() -> dict[str, bool]:
    return {
        platform: _worker_environment(platform) is not None
        for platform in ("Windows", "macOS", "Linux")
    }


def _validate_findings(findings: list[Any]) -> None:
    allowed_statuses = {"FINDING", "REVIEW_REQUIRED", "NOT_VERIFIED"}
    allowed_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("invalid finding")
        if str(item.get("status", "")).upper() not in allowed_statuses:
            raise ValueError("invalid finding status")
        if str(item.get("severity", "")).upper() not in allowed_severities:
            raise ValueError("invalid finding severity")
        confidence = float(item.get("confidence", -1))
        if not 0 <= confidence <= 1:
            raise ValueError("invalid finding confidence")
        for key in ("title", "vulnerability_type", "evidence", "source"):
            value = item.get(key)
            if not isinstance(value, str) or len(value) > MAX_DIAGNOSTIC_CHARS:
                raise ValueError("invalid finding text")


def inspect_native_artifact(path: Path, platform: str) -> ScannerResult:
    """Send an immutable artifact and accept only bounded, attested evidence."""
    configured = _worker_environment(platform)
    if configured is None:
        return ScannerResult(
            "desktop_artifact",
            ScannerStatus.PARTIAL,
            errors=[f"No valid attested {platform} desktop worker is configured"],
        )
    try:
        size = path.stat().st_size
    except OSError:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=["Native artifact could not be read"],
        )
    if size < 1 or size > MAX_ARTIFACT_BYTES:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=["Native artifact size is outside the worker contract"],
        )
    try:
        artifact = path.read_bytes()
    except OSError:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=["Native artifact could not be read"],
        )
    if len(artifact) != size:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=["Native artifact changed while it was being read"],
        )

    url, token, launcher_key = configured
    digest = hashlib.sha256(artifact).hexdigest()
    nonce = secrets.token_hex(32)
    artifact_type = _artifact_type(path.name)
    if artifact_type is None:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=["Native artifact type is outside the worker contract"],
        )
    required_checks = sorted(REQUIRED_CHECKS[artifact_type])
    policy = {
        "policy_id": POLICY_ID,
        "artifact_type": artifact_type,
        "required_checks": required_checks,
        "max_artifact_bytes": MAX_ARTIFACT_BYTES,
        "max_findings": MAX_FINDINGS,
        "max_diagnostic_chars": MAX_DIAGNOSTIC_CHARS,
        "isolation": REQUIRED_ISOLATION,
    }
    policy_sha256 = hashlib.sha256(_stable_json(policy)).hexdigest()
    request = {
        "request_nonce": nonce,
        "platform": platform,
        "artifact": {
            "name": path.name,
            "size_bytes": len(artifact),
            "sha256": digest,
            "data_base64": base64.b64encode(artifact).decode(),
        },
        "policy": policy,
        "policy_sha256": policy_sha256,
    }
    try:
        with httpx.Client(timeout=330) as client:
            response = client.post(
                url.rstrip("/") + "/v1/inspect",
                headers={"Authorization": f"Bearer {token}"},
                json=request,
            )
    except httpx.HTTPError:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=[f"{platform} desktop worker request failed"],
        )
    if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=[f"{platform} desktop worker rejected the artifact"],
        )

    try:
        data = response.json()
        receipt, worker_key = _verify_launcher_receipt(
            data["launcher_receipt"], launcher_key, platform
        )
        worker_key.verify(
            base64.b64decode(data["worker_signature"], validate=True),
            _attestation_body(data),
        )
        receipt_digest = hashlib.sha256(_stable_json(receipt)).hexdigest()
        if (
            data["job_status"] != "COMPLETED"
            or data["request_nonce"] != nonce
            or data["artifact_sha256"] != digest
            or data["platform"] != platform
            or data["policy_id"] != POLICY_ID
            or data["policy_sha256"] != policy_sha256
            or data["isolation"] != REQUIRED_ISOLATION
            or data["isolation_receipt_sha256"] != receipt_digest
            or data["launcher_id"] != receipt["launcher_id"]
            or data["sandbox_id"] != receipt["sandbox_id"]
            or data["worker_instance_id"] != receipt["worker_instance_id"]
            or data["resource_limits"] != receipt["resource_limits"]
        ):
            raise ValueError("request binding mismatch")
        runtime_isolation = data["runtime_isolation"]
        resource_limits = data["resource_limits"]
        if (
            not isinstance(data["isolation_receipt_sha256"], str)
            or len(data["isolation_receipt_sha256"]) != 64
            or not isinstance(data["launcher_id"], str)
            or not data["launcher_id"]
            or not isinstance(data["sandbox_id"], str)
            or not data["sandbox_id"]
            or not isinstance(runtime_isolation, dict)
            or not runtime_isolation
            or any(value is not True for value in runtime_isolation.values())
            or not isinstance(resource_limits, dict)
            or any(
                not isinstance(resource_limits.get(name), int)
                or resource_limits[name] < 1
                for name in (
                    "cpu_count", "memory_mib", "disk_mib", "processes",
                    "timeout_seconds",
                )
            )
            or resource_limits["timeout_seconds"] > 300
        ):
            raise ValueError("invalid isolation evidence")
        findings = data["findings"]
        coverage = data["coverage"]
        tool_versions = data["tool_versions"]
        if (
            not isinstance(findings, list)
            or len(findings) > MAX_FINDINGS
            or not isinstance(coverage, dict)
            or not isinstance(tool_versions, dict)
        ):
            raise ValueError("invalid evidence shape")
        _validate_findings(findings)
        if (
            len(tool_versions) > 64
            or any(
                not isinstance(key, str)
                or len(key) > 100
                or (value is not None and (
                    not isinstance(value, str) or len(value) > 500
                ))
                for key, value in tool_versions.items()
            )
        ):
            raise ValueError("invalid tool versions")
        checks = coverage.get("checks")
        if (
            not isinstance(coverage.get("complete"), bool)
            or not isinstance(checks, dict)
            or any(not isinstance(key, str) or not isinstance(value, bool)
                   for key, value in checks.items())
            or not REQUIRED_CHECKS[artifact_type].issubset(checks)
        ):
            raise ValueError("invalid coverage contract")
        evidence = {
            "findings": findings,
            "coverage": coverage,
            "diagnostics": data.get("diagnostics", []),
        }
        if hashlib.sha256(_stable_json(evidence)).hexdigest() != data["evidence_sha256"]:
            raise ValueError("evidence digest mismatch")
        diagnostics = data.get("diagnostics", [])
        if (
            not isinstance(diagnostics, list)
            or any(len(str(item)) > MAX_DIAGNOSTIC_CHARS for item in diagnostics)
        ):
            raise ValueError("invalid diagnostics")
        complete = (
            coverage["complete"]
            and all(checks[name] for name in REQUIRED_CHECKS[artifact_type])
        )
        worker_instance_id = receipt["worker_instance_id"]
        _consume_worker_instance(worker_instance_id)
        return ScannerResult(
            "desktop_artifact",
            ScannerStatus.SUCCESS if complete else ScannerStatus.PARTIAL,
            findings=findings,
            errors=[] if complete else [
                f"{platform} worker reported incomplete native inspection coverage"
            ],
            metadata={
                "verified_attestation": True,
                "job_id": str(data["job_id"]),
                "artifact_sha256": digest,
                "platform": platform,
                "policy_id": POLICY_ID,
                "coverage": coverage,
                "tool_versions": tool_versions,
                "isolation": dict(data["isolation"]),
                "isolation_receipt_sha256": data["isolation_receipt_sha256"],
                "launcher_id": data["launcher_id"],
                "sandbox_id": data["sandbox_id"],
                "worker_instance_id": data["worker_instance_id"],
                "resource_limits": dict(resource_limits),
                "runtime_isolation": dict(runtime_isolation),
                "diagnostics": list(map(str, diagnostics)),
            },
        )
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return ScannerResult(
            "desktop_artifact", ScannerStatus.FAILED,
            errors=[f"{platform} desktop worker returned invalid evidence"],
        )
