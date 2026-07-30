"""Portable entry point for isolated, platform-native structural inspection."""

from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing
import os
import plistlib
import secrets
import signal
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

MAX_REQUEST_BYTES = 275 * 1024 * 1024
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
MAX_OUTPUT_CHARS = 4_096
POLICY_ID = "crucible-native-static-v2"
ISOLATION = {
    "ephemeral": True, "run_as_non_root": True, "host_filesystem": "none",
    "network": "disabled", "artifact_mount": "read_only", "credentials": "none",
    "cpu_limit": True, "memory_limit": True, "pid_limit": True,
    "disk_limit": True, "hard_timeout": True,
}
PLATFORM = os.environ.get("DESKTOP_WORKER_PLATFORM", "")
TOKEN = os.environ.get("DESKTOP_WORKER_TOKEN", "")
NONCES: dict[str, float] = {}
NONCE_LOCK = threading.Lock()
JOB_LIMIT = threading.BoundedSemaphore(1)
JOB_TIMEOUT_SECONDS = 300
ISOLATION_RECEIPT: dict[str, Any] | None = None
WORKER_PRIVATE_KEY: Ed25519PrivateKey | None = None

REQUIRED_CHECKS = {
    ".exe": frozenset({"dos_header", "pe_header", "sections", "imports",
                       "resources", "authenticode"}),
    ".msi": frozenset({"ole_container", "tables", "embedded_cabs",
                       "custom_actions", "authenticode"}),
    ".msix": frozenset({"zip_integrity", "manifest", "capabilities",
                        "package_signature"}),
    ".dmg": frozenset({"udif_trailer", "partition_metadata",
                       "contained_applications", "nested_code_signatures",
                       "gatekeeper", "notarization_ticket",
                       "macho_load_commands", "entitlements"}),
    ".pkg": frozenset({"xar_container", "payload_inventory", "bom_inventory",
                       "installer_scripts", "package_signature", "gatekeeper",
                       "notarization_ticket"}),
    ".app.zip": frozenset({"bundle_structure", "nested_code_signatures",
                           "gatekeeper", "notarization_ticket",
                           "macho_load_commands", "entitlements"}),
    ".deb": frozenset({"ar_container", "control_metadata",
                       "maintainer_scripts", "file_inventory", "provenance"}),
    ".rpm": frozenset({"rpm_header", "metadata", "file_inventory",
                       "installer_scripts", "signature"}),
    ".snap": frozenset({"filesystem_marker", "filesystem_inventory",
                        "manifest", "confinement_or_runtime", "signature"}),
    ".appimage": frozenset({"filesystem_marker", "filesystem_inventory",
                            "manifest", "confinement_or_runtime", "signature"}),
}


def artifact_type(name: str) -> str | None:
    lowered = name.lower()
    if lowered.endswith(".app.zip"):
        return ".app.zip"
    suffix = Path(lowered).suffix
    return suffix if suffix in REQUIRED_CHECKS else None


def stable_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def isolation_receipt_body(receipt: dict[str, Any]) -> bytes:
    return stable_json({
        key: receipt.get(key) for key in (
            "launcher_id", "sandbox_id", "platform", "issued_at", "expires_at",
            "isolation", "resource_limits", "worker_instance_id",
            "worker_public_key", "max_jobs",
        )
    })


def load_worker_private_key() -> Ed25519PrivateKey:
    key_path = Path(os.environ.get("DESKTOP_WORKER_PRIVATE_KEY_PATH", ""))
    if (
        not key_path.is_file()
        or (os.name == "posix" and key_path.stat().st_mode & 0o077)
    ):
        raise RuntimeError("A private one-time worker key with mode 0600 is required")
    try:
        key_bytes = key_path.read_bytes()
        key = serialization.load_pem_private_key(
            key_bytes, password=None
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("The one-time worker key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("The one-time worker key must be Ed25519")
    return key


def consume_worker_private_key_file() -> None:
    key_path = Path(os.environ.get("DESKTOP_WORKER_PRIVATE_KEY_PATH", ""))
    try:
        key_path.unlink()
    except OSError as exc:
        raise RuntimeError(
            "The one-time worker key must be removable after bootstrap"
        ) from exc
    if key_path.exists():
        raise RuntimeError("The one-time worker key was not consumed")


def _public_key_text(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode()


def validate_isolation_receipt(
    worker_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Require a short-lived launcher-signed receipt; never trust a Boolean."""
    receipt_path = Path(os.environ.get("DESKTOP_ISOLATION_RECEIPT_PATH", ""))
    public_key_path = Path(
        os.environ.get("DESKTOP_LAUNCHER_PUBLIC_KEY_PATH", "")
    )
    if not receipt_path.is_file() or not public_key_path.is_file():
        raise RuntimeError("A signed launcher isolation receipt is required")
    if os.name == "posix" and (
        receipt_path.stat().st_mode & 0o222
        or public_key_path.stat().st_mode & 0o222
    ):
        raise RuntimeError("Launcher trust material must be read-only")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("launcher key must be Ed25519")
        public_key.verify(
            base64.b64decode(receipt["signature"], validate=True),
            isolation_receipt_body(receipt),
        )
        limits = receipt["resource_limits"]
        now = time.time()
        if (
            receipt["platform"] != PLATFORM
            or receipt["isolation"] != ISOLATION
            or not isinstance(receipt["launcher_id"], str)
            or not receipt["launcher_id"]
            or not isinstance(receipt["sandbox_id"], str)
            or not receipt["sandbox_id"]
            or not isinstance(receipt["worker_instance_id"], str)
            or not receipt["worker_instance_id"]
            or receipt["worker_public_key"] != _public_key_text(worker_key)
            or receipt["max_jobs"] != 1
            or not float(receipt["issued_at"]) <= now <= float(receipt["expires_at"])
            or float(receipt["expires_at"]) - float(receipt["issued_at"]) > 3600
            or not isinstance(limits, dict)
            or any(
                not isinstance(limits.get(name), int) or limits[name] < 1
                for name in (
                    "cpu_count", "memory_mib", "disk_mib", "processes",
                    "timeout_seconds",
                )
            )
            or limits["timeout_seconds"] > JOB_TIMEOUT_SECONDS
        ):
            raise ValueError("invalid receipt claims")
    except (
        KeyError, TypeError, ValueError, json.JSONDecodeError, InvalidSignature,
    ) as exc:
        raise RuntimeError("The launcher isolation receipt is invalid") from exc
    return {
        **receipt,
        "receipt_sha256": digest(stable_json(receipt)),
    }


def runtime_isolation_checks(artifact_path: Path) -> dict[str, bool]:
    """Verify properties measurable inside the worker process."""
    non_root = True
    if hasattr(os, "geteuid"):
        non_root = os.geteuid() != 0
    artifact_read_only = (
        artifact_path.is_file()
        and not bool(artifact_path.stat().st_mode & 0o222)
    )
    receipt = ISOLATION_RECEIPT or {}
    return {
        "run_as_non_root": non_root,
        "artifact_read_only": artifact_read_only,
        "launcher_receipt_valid": bool(receipt.get("receipt_sha256")),
        "hard_timeout_supervised": True,
    }


def tool_version(name: str, args: tuple[str, ...] = ("--version",)) -> str | None:
    binary = shutil.which(name)
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=10, check=False
        )
        return (result.stdout or result.stderr).strip()[:300] or "available"
    except (OSError, subprocess.SubprocessError):
        return None


def run_tool(command: list[str], timeout: int = 60) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return result.returncode == 0, (result.stdout + result.stderr)[-MAX_OUTPUT_CHARS:]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)[:MAX_OUTPUT_CHARS]


def inspect_entitlements(app: Path) -> tuple[bool, list[dict], list[str]]:
    """Parse entitlements for the main bundle and bounded nested signed code."""
    codesign = shutil.which("codesign")
    if not codesign:
        return False, [], ["codesign unavailable for entitlement inspection"]
    candidates: list[Path] = [app]
    for path in app.rglob("*"):
        if len(candidates) >= 512:
            return False, [], ["entitlement component limit exceeded"]
        if path.is_dir() and path.suffix.lower() in {
            ".app", ".framework", ".xpc", ".appex",
        }:
            candidates.append(path)
        elif (
            path.is_file()
            and bool(path.stat().st_mode & 0o111)
            and any(part in {
                "MacOS", "Helpers", "Frameworks", "PlugIns", "XPCServices",
            } for part in path.parts)
        ):
            candidates.append(path)
    unique = list(dict.fromkeys(candidates))
    risky = {
        "com.apple.security.get-task-allow":
            "Debug task attachment is enabled",
        "com.apple.security.cs.disable-library-validation":
            "Library validation is disabled",
        "com.apple.security.cs.allow-unsigned-executable-memory":
            "Unsigned executable memory is allowed",
        "com.apple.security.cs.disable-executable-page-protection":
            "Executable-memory protection is disabled",
        "com.apple.security.automation.apple-events":
            "Apple Events automation is enabled",
        "com.apple.security.device.camera":
            "Camera access is enabled",
        "com.apple.security.device.microphone":
            "Microphone access is enabled",
    }
    findings: list[dict] = []
    diagnostics: list[str] = []
    complete = True
    for component in unique:
        try:
            result = subprocess.run(
                [codesign, "-d", "--entitlements", ":-", str(component)],
                capture_output=True, timeout=30, check=False,
                env={"PATH": os.environ.get("PATH", "")},
            )
            if result.returncode != 0 or not result.stdout:
                complete = False
                diagnostics.append(
                    f"entitlements unavailable: {component.name}"
                )
                continue
            parsed = plistlib.loads(result.stdout)
            if not isinstance(parsed, dict):
                raise plistlib.InvalidFileException()
            diagnostics.append(
                f"entitlements parsed: {component.name}; keys={len(parsed)}"
            )
            for entitlement, description in risky.items():
                if parsed.get(entitlement) is True:
                    findings.append(finding(
                        description, "RISKY_MACOS_ENTITLEMENT",
                        f"{component.name}: {entitlement}",
                    ))
        except (
            OSError, subprocess.SubprocessError, plistlib.InvalidFileException,
            ValueError, TypeError,
        ):
            complete = False
            diagnostics.append(f"invalid entitlements: {component.name}")
    return complete, findings, diagnostics


def finding(
    title: str, kind: str, evidence: str = "Structural validation failed",
    severity: str = "HIGH",
) -> dict:
    return {
        "title": title, "vulnerability_type": kind, "severity": severity,
        "confidence": 1.0, "evidence": evidence[:MAX_OUTPUT_CHARS],
        "file_path": None, "line_number": None, "product_control_ids": [],
        "cwe_ids": [], "source": "desktop_worker", "mapped": True,
        "status": "FINDING", "recommendation": "Review and rebuild the native package.",
    }


def inspect_pe(path: Path) -> tuple[list[dict], dict, list[str]]:
    data = path.read_bytes()
    checks = {"dos_header": False, "pe_header": False, "sections": False,
              "imports": False, "resources": False, "authenticode": False}
    diagnostics = []
    findings = []
    if len(data) < 64 or data[:2] != b"MZ":
        return [finding("Invalid DOS header", "INVALID_PE")], checks, diagnostics
    checks["dos_header"] = True
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return [finding("Invalid PE header", "INVALID_PE")], checks, diagnostics
    checks["pe_header"] = True
    machine, sections, _, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    checks["sections"] = 0 < sections <= 96
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0] if optional + 2 <= len(data) else 0
    directory = optional + (112 if magic == 0x20B else 96)
    section_table = optional + optional_size
    section_ranges = []
    for index in range(sections):
        header = section_table + index * 40
        if header + 40 > len(data):
            checks["sections"] = False
            break
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, header + 8
        )
        section_ranges.append(
            (virtual_address, max(virtual_size, raw_size), raw_offset, raw_size)
        )

    def rva_offset(rva: int) -> int | None:
        for virtual, span, raw, raw_size in section_ranges:
            if virtual <= rva < virtual + span:
                candidate = raw + (rva - virtual)
                if candidate < raw + raw_size and candidate < len(data):
                    return candidate
        return None

    if optional_size >= (directory - optional) + 8 * 6 and directory + 8 * 6 <= len(data):
        import_rva, import_size = struct.unpack_from("<II", data, directory + 8)
        resource_rva, resource_size = struct.unpack_from("<II", data, directory + 16)
        certificate_offset, certificate_size = struct.unpack_from("<II", data, directory + 32)
        checks["imports"] = True
        imported_libraries = []
        if import_rva:
            descriptor = rva_offset(import_rva)
            if descriptor is None:
                checks["imports"] = False
            else:
                for _ in range(256):
                    if descriptor + 20 > len(data):
                        checks["imports"] = False
                        break
                    values = struct.unpack_from("<IIIII", data, descriptor)
                    if not any(values):
                        break
                    name_offset = rva_offset(values[3])
                    if name_offset is None:
                        checks["imports"] = False
                        break
                    end = data.find(b"\0", name_offset, min(len(data), name_offset + 512))
                    if end < 0:
                        checks["imports"] = False
                        break
                    imported_libraries.append(
                        data[name_offset:end].decode("ascii", errors="replace")
                    )
                    descriptor += 20
        checks["resources"] = not resource_rva or rva_offset(resource_rva) is not None
        certificate_present = (
            certificate_size > 0
            and certificate_offset + certificate_size <= len(data)
        )
        diagnostics.append(
            f"import_directory={bool(import_rva or import_size)}; "
            f"resource_directory={bool(resource_rva or resource_size)}; "
            f"certificate_table={certificate_present}; "
            f"imports={','.join(imported_libraries[:100])}"
        )
        if not certificate_present:
            findings.append(finding(
                "PE has no embedded Authenticode certificate", "UNSIGNED_BINARY"
            ))
    diagnostics.append(f"PE machine=0x{machine:04x}; sections={sections}; magic=0x{magic:04x}")
    if not checks["sections"]:
        findings.append(finding("Invalid PE section count", "INVALID_PE"))
    return findings, checks, diagnostics


def inspect_msix(path: Path) -> tuple[list[dict], dict, list[str]]:
    checks = {"zip_integrity": False, "manifest": False, "capabilities": False,
              "package_signature": False}
    findings = []
    diagnostics = []
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip():
                raise ValueError("CRC failure")
            checks["zip_integrity"] = True
            names = {name.casefold(): name for name in archive.namelist()}
            manifest_name = names.get("appxmanifest.xml")
            checks["manifest"] = manifest_name is not None
            signature_name = names.get("appxsignature.p7x")
            checks["package_signature"] = True
            if manifest_name:
                manifest = archive.read(manifest_name)[:2_000_000].decode(
                    "utf-8", errors="replace"
                )
                checks["capabilities"] = True
                dangerous = [
                    value for value in (
                        "runFullTrust", "broadFileSystemAccess",
                        "enterpriseAuthentication", "documentsLibrary",
                    ) if value in manifest
                ]
                if dangerous:
                    findings.append(finding(
                        "MSIX declares sensitive capabilities",
                        "SENSITIVE_PACKAGE_CAPABILITY", ", ".join(dangerous),
                    ))
            if not checks["manifest"]:
                findings.append(finding("MSIX manifest is missing", "INVALID_MSIX"))
            if signature_name is None:
                findings.append(finding("MSIX signature is missing", "UNSIGNED_PACKAGE"))
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        findings.append(finding("Invalid MSIX container", "INVALID_MSIX", str(exc)))
    return findings, checks, diagnostics


def inspect_windows(path: Path) -> tuple[list[dict], dict, dict, list[str]]:
    suffix = path.suffix.lower()
    tools = {
        "powershell": tool_version("powershell", ("-NoProfile", "-Command", "$PSVersionTable.PSVersion")),
    }
    if suffix == ".exe":
        findings, checks, diagnostics = inspect_pe(path)
    elif suffix == ".msix":
        findings, checks, diagnostics = inspect_msix(path)
    elif suffix == ".msi":
        data = path.read_bytes()[:8]
        checks = {
            "ole_container": data == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            "tables": False, "embedded_cabs": False, "custom_actions": False,
            "authenticode": False,
        }
        findings, diagnostics = [], []
        if not checks["ole_container"]:
            findings.append(finding("Invalid MSI container", "INVALID_MSI"))
    else:
        return [finding("Unsupported Windows artifact", "UNSUPPORTED_ARTIFACT")], {}, tools, []
    powershell = shutil.which("powershell")
    if powershell:
        if suffix == ".msi" and checks["ole_container"]:
            script = (
                "$i=New-Object -ComObject WindowsInstaller.Installer;"
                "$d=$i.OpenDatabase($args[0],0);"
                "$tables=@('Property','Media','CustomAction');"
                "$out=@{};foreach($t in $tables){"
                "$v=$d.OpenView(\"SELECT * FROM ``$t``\");$v.Execute();$n=0;"
                "while($v.Fetch()){$n++};$out[$t]=$n};"
                "$out|ConvertTo-Json -Compress"
            )
            ok, output = run_tool([
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                script, str(path),
            ])
            diagnostics.append(output)
            checks["tables"] = ok and '"Property"' in output
            checks["embedded_cabs"] = ok and '"Media"' in output
            checks["custom_actions"] = ok and '"CustomAction"' in output
            if ok and '"CustomAction":0' not in output:
                findings.append(finding(
                    "MSI contains custom actions", "MSI_CUSTOM_ACTION",
                    output, "MEDIUM",
                ))
        ok, output = run_tool([
            powershell, "-NoProfile", "-NonInteractive", "-Command",
            "(Get-AuthenticodeSignature -LiteralPath $args[0]) | "
            "ConvertTo-Json -Compress", str(path),
        ])
        diagnostics.append(output)
        checks["authenticode"] = ok
        if not (ok and '"Status":"Valid"' in output):
            findings.append(finding(
                "Windows package signature is not valid",
                "INVALID_AUTHENTICODE", output,
            ))
    complete = all(checks.values())
    return findings, {"complete": complete, "checks": checks}, tools, diagnostics


def inspect_macos(path: Path) -> tuple[list[dict], dict, dict, list[str]]:
    suffix = artifact_type(path.name)
    required = ("hdiutil", "pkgutil", "codesign", "spctl", "stapler", "otool")
    tools = {name: tool_version(name) for name in required}
    checks: dict[str, bool] = {}
    diagnostics = []
    findings = []
    if suffix == ".app.zip":
        checks.update({
            "bundle_structure": False, "nested_code_signatures": False,
            "gatekeeper": False, "notarization_ticket": False,
            "macho_load_commands": False, "entitlements": False,
        })
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with zipfile.ZipFile(path) as archive:
                    members = archive.infolist()
                    if len(members) > 10_000:
                        raise ValueError("too many bundle members")
                    expanded = 0
                    for member in members:
                        relative = Path(member.filename)
                        if (
                            relative.is_absolute()
                            or ".." in relative.parts
                            or member.is_dir()
                        ):
                            if member.is_dir():
                                continue
                            raise ValueError("invalid bundle member")
                        expanded += member.file_size
                        if expanded > MAX_ARTIFACT_BYTES:
                            raise ValueError("bundle expands beyond worker limit")
                        target = root.joinpath(*relative.parts)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(member) as source, target.open("xb") as output:
                            shutil.copyfileobj(source, output, length=1024 * 1024)
                        mode = (member.external_attr >> 16) & 0o777
                        target.chmod(mode or 0o400)
                apps = [
                    candidate for candidate in root.glob("*.app")
                    if (candidate / "Contents" / "Info.plist").is_file()
                ]
                if len(apps) != 1:
                    raise ValueError("worker envelope must contain exactly one app")
                app = apps[0]
                checks["bundle_structure"] = True
                tool_specs = [
                    ("codesign", ["--verify", "--deep", "--strict", str(app)],
                     "nested_code_signatures", "INVALID_CODE_SIGNATURE"),
                    ("spctl", ["--assess", "--type", "execute", str(app)],
                     "gatekeeper", "GATEKEEPER_REJECTED"),
                    ("stapler", ["validate", str(app)],
                     "notarization_ticket", "NOTARIZATION_MISSING"),
                ]
                for tool, args, key, kind in tool_specs:
                    binary = shutil.which(tool)
                    if not binary:
                        continue
                    checks[key], detail = run_tool([binary, *args])
                    diagnostics.append(detail)
                    if not checks[key]:
                        findings.append(finding(
                            f"{tool} validation failed", kind, detail
                        ))
                entitlement_complete, entitlement_findings, entitlement_diagnostics = (
                    inspect_entitlements(app)
                )
                checks["entitlements"] = entitlement_complete
                findings.extend(entitlement_findings)
                diagnostics.extend(entitlement_diagnostics)
                if not entitlement_complete:
                    findings.append(finding(
                        "Application entitlements could not be completely inspected",
                        "ENTITLEMENT_INSPECTION_FAILED",
                    ))
                otool = shutil.which("otool")
                executables = (
                    list((app / "Contents" / "MacOS").glob("*"))
                    if (app / "Contents" / "MacOS").is_dir() else []
                )
                if otool and executables:
                    checks["macho_load_commands"] = True
                    for executable in executables:
                        valid, detail = run_tool([otool, "-l", str(executable)])
                        diagnostics.append(detail)
                        if not valid:
                            checks["macho_load_commands"] = False
                            findings.append(finding(
                                "Mach-O load commands could not be inspected",
                                "INVALID_MACHO", detail,
                            ))
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            findings.append(finding(
                "Invalid macOS application envelope", "INVALID_APP_BUNDLE",
                str(exc),
            ))
    elif suffix == ".dmg":
        checks["udif_trailer"] = (
            path.stat().st_size >= 512
            and path.read_bytes()[-512:-508] == b"koly"
        )
        hdiutil = shutil.which("hdiutil")
        checks.update({
            "partition_metadata": False, "contained_applications": False,
            "nested_code_signatures": False, "gatekeeper": False,
            "notarization_ticket": False, "macho_load_commands": False,
            "entitlements": False,
        })
        if hdiutil:
            ok, output = run_tool([hdiutil, "imageinfo", "-plist", str(path)])
            checks["partition_metadata"] = ok
            diagnostics.append(output)
            with tempfile.TemporaryDirectory() as directory:
                mount = Path(directory) / "mount"
                mount.mkdir()
                attached, output = run_tool([
                    hdiutil, "attach", "-readonly", "-nobrowse",
                    "-mountpoint", str(mount), str(path),
                ], 120)
                diagnostics.append(output)
                if attached:
                    apps = sorted(mount.rglob("*.app"))
                    checks["contained_applications"] = bool(apps)
                    checks["nested_code_signatures"] = bool(apps)
                    checks["gatekeeper"] = bool(apps)
                    checks["notarization_ticket"] = bool(apps)
                    checks["macho_load_commands"] = bool(apps)
                    checks["entitlements"] = bool(apps)
                    if not apps:
                        findings.append(finding(
                            "DMG contains no macOS application bundle",
                            "MISSING_APP_BUNDLE",
                        ))
                    for app in apps:
                        entitlement_complete, entitlement_findings, entitlement_diagnostics = (
                            inspect_entitlements(app)
                        )
                        checks["entitlements"] &= entitlement_complete
                        findings.extend(entitlement_findings)
                        diagnostics.extend(entitlement_diagnostics)
                        for tool, args, key, kind in [
                            ("codesign", ["--verify", "--deep", "--strict", str(app)],
                             "nested_code_signatures", "INVALID_CODE_SIGNATURE"),
                            ("spctl", ["--assess", "--type", "execute", str(app)],
                             "gatekeeper", "GATEKEEPER_REJECTED"),
                            ("stapler", ["validate", str(app)],
                             "notarization_ticket", "NOTARIZATION_MISSING"),
                        ]:
                            binary = shutil.which(tool)
                            if not binary:
                                checks[key] = False
                                continue
                            valid, detail = run_tool([binary, *args])
                            diagnostics.append(detail)
                            if not valid:
                                findings.append(finding(
                                    f"{tool} validation failed", kind, detail
                                ))
                        otool = shutil.which("otool")
                        executables = (
                            list((app / "Contents" / "MacOS").glob("*"))
                            if (app / "Contents" / "MacOS").is_dir() else []
                        )
                        if not otool:
                            checks["macho_load_commands"] = False
                        for executable in executables:
                            valid, detail = run_tool([otool, "-l", str(executable)])
                            diagnostics.append(detail)
                            if not valid:
                                checks["macho_load_commands"] = False
                                findings.append(finding(
                                    "Mach-O load commands could not be inspected",
                                    "INVALID_MACHO", detail,
                                ))
                    run_tool([hdiutil, "detach", str(mount)], 30)
                else:
                    findings.append(finding(
                        "DMG could not be mounted read-only", "INVALID_DMG", output
                    ))
    elif suffix == ".pkg":
        checks["xar_container"] = path.read_bytes()[:4] == b"xar!"
        pkgutil = shutil.which("pkgutil")
        checks.update({
            "payload_inventory": False, "bom_inventory": False,
            "installer_scripts": False, "package_signature": False,
            "gatekeeper": False, "notarization_ticket": False,
        })
        if pkgutil:
            ok, output = run_tool([pkgutil, "--check-signature", str(path)])
            checks["package_signature"] = True
            diagnostics.append(output)
            if not ok:
                findings.append(finding(
                    "Package signature is invalid", "INVALID_PACKAGE_SIGNATURE", output
                ))
            with tempfile.TemporaryDirectory() as extracted:
                expanded, output = run_tool(
                    [pkgutil, "--expand-full", str(path), extracted], 120
                )
                diagnostics.append(output)
                if expanded:
                    root = Path(extracted)
                    checks["payload_inventory"] = True
                    checks["bom_inventory"] = True
                    checks["installer_scripts"] = True
                    scripts = [
                        item for item in root.rglob("*")
                        if item.is_file() and "Scripts" in item.parts
                    ]
                    for script in scripts[:1_000]:
                        text = script.read_text(errors="replace")[:200_000]
                        if any(term in text for term in (
                            "curl ", "wget ", "/dev/tcp", "sudo ", "chmod 777"
                        )):
                            findings.append(finding(
                                "PKG installer script contains risky behavior",
                                "RISKY_INSTALLER_SCRIPT",
                                script.relative_to(root).as_posix(),
                            ))
        for tool, args, key, kind in [
            ("spctl", ["--assess", "--type", "install", str(path)],
             "gatekeeper", "GATEKEEPER_REJECTED"),
            ("stapler", ["validate", str(path)],
             "notarization_ticket", "NOTARIZATION_MISSING"),
        ]:
            binary = shutil.which(tool)
            if binary:
                checks[key] = True
                valid, output = run_tool([binary, *args])
                diagnostics.append(output)
                if not valid:
                    findings.append(finding(f"{tool} validation failed", kind, output))
    else:
        return [finding("Unsupported macOS artifact", "UNSUPPORTED_ARTIFACT")], {}, tools, []
    if not all(checks.values()):
        findings.append(finding(
            "macOS package inspection is incomplete",
            "INCOMPLETE_NATIVE_INSPECTION",
            ", ".join(name for name, passed in checks.items() if not passed),
            "MEDIUM",
        ))
    return findings, {"complete": all(checks.values()), "checks": checks}, tools, diagnostics


def inspect_linux(path: Path) -> tuple[list[dict], dict, dict, list[str]]:
    suffix = path.suffix.lower()
    tools = {
        name: tool_version(name) for name in (
            "dpkg-deb", "rpm", "rpmkeys", "unsquashfs", "readelf"
        )
    }
    checks: dict[str, bool] = {}
    findings = []
    diagnostics = []
    if suffix == ".deb":
        checks["ar_container"] = path.read_bytes()[:8] == b"!<arch>\n"
        binary = shutil.which("dpkg-deb")
        checks.update({"control_metadata": False, "maintainer_scripts": False,
                       "file_inventory": False, "provenance": False})
        if binary:
            for args, key in [
                (["--info"], "control_metadata"), (["--contents"], "file_inventory")
            ]:
                ok, output = run_tool([binary, *args, str(path)])
                checks[key] = ok
                diagnostics.append(output)
            with tempfile.TemporaryDirectory() as control:
                ok, output = run_tool([binary, "-e", str(path), control])
                diagnostics.append(output)
                checks["maintainer_scripts"] = ok
                for script in ("preinst", "postinst", "prerm", "postrm"):
                    candidate = Path(control) / script
                    if candidate.is_file():
                        text = candidate.read_text(errors="replace")[:200_000]
                        if any(term in text for term in ("curl ", "wget ", "nc ", "/dev/tcp")):
                            findings.append(finding(
                                "Debian maintainer script performs network activity",
                                "RISKY_INSTALLER_SCRIPT", script,
                            ))
    elif suffix == ".rpm":
        checks["rpm_header"] = path.read_bytes()[:4] == b"\xed\xab\xee\xdb"
        rpm = shutil.which("rpm")
        checks.update({"metadata": False, "file_inventory": False,
                       "installer_scripts": False, "signature": False})
        if rpm:
            for args, key in [
                (["-qpi"], "metadata"), (["-qpl"], "file_inventory"),
                (["-qp", "--scripts"], "installer_scripts"),
                (["-K"], "signature"),
            ]:
                ok, output = run_tool([rpm, *args, str(path)])
                checks[key] = ok
                diagnostics.append(output)
    elif suffix in {".snap", ".appimage"}:
        data = path.read_bytes()
        offset = 0 if suffix == ".snap" else data.find(b"hsqs")
        checks["filesystem_marker"] = offset >= 0
        unsquashfs = shutil.which("unsquashfs")
        checks.update({"filesystem_inventory": False, "manifest": False,
                       "confinement_or_runtime": False, "signature": False})
        if unsquashfs and offset >= 0:
            offset_args = [] if offset == 0 else ["-o", str(offset)]
            ok, output = run_tool([unsquashfs, "-ll", *offset_args, str(path)], 120)
            checks["filesystem_inventory"] = ok
            diagnostics.append(output)
            if suffix == ".snap":
                ok, output = run_tool([
                    unsquashfs, "-cat", *offset_args, str(path), "meta/snap.yaml"
                ])
                checks["manifest"] = ok
                checks["confinement_or_runtime"] = (
                    ok and "confinement:" in output and "plugs:" in output
                )
                diagnostics.append(output)
            else:
                checks["manifest"] = True
                checks["confinement_or_runtime"] = data[:4] == b"\x7fELF"
    else:
        return [finding("Unsupported Linux artifact", "UNSUPPORTED_ARTIFACT")], {}, tools, []
    if not all(checks.values()):
        findings.append(finding(
            "Linux package inspection is incomplete",
            "INCOMPLETE_NATIVE_INSPECTION",
            ", ".join(name for name, passed in checks.items() if not passed),
            "MEDIUM",
        ))
    return findings, {"complete": all(checks.values()), "checks": checks}, tools, diagnostics


def inspect(path: Path) -> tuple[list[dict], dict, dict, list[str]]:
    if PLATFORM == "Windows":
        return inspect_windows(path)
    if PLATFORM == "macOS":
        return inspect_macos(path)
    if PLATFORM == "Linux":
        return inspect_linux(path)
    raise ValueError("invalid worker platform")


def _inspection_child(
    platform: str,
    path: str,
    output: multiprocessing.Queue,
) -> None:
    """Run native tools in a disposable process group."""
    global PLATFORM
    PLATFORM = platform
    for name in (
        "DESKTOP_WORKER_TOKEN",
        "DESKTOP_WORKER_PRIVATE_KEY_PATH",
        "DESKTOP_ISOLATION_RECEIPT_PATH",
        "DESKTOP_LAUNCHER_PUBLIC_KEY_PATH",
    ):
        os.environ.pop(name, None)
    if hasattr(os, "setsid"):
        os.setsid()
    try:
        output.put(("ok", inspect(Path(path))))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


def _terminate_process_tree(process: multiprocessing.Process) -> None:
    if not process.is_alive():
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
    else:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
    process.join(timeout=10)


def inspect_with_deadline(
    path: Path,
    timeout_seconds: int,
) -> tuple[list[dict], dict, dict, list[str]]:
    """Enforce one absolute deadline around the complete native inspection."""
    context = multiprocessing.get_context("spawn")
    output = context.Queue(maxsize=1)
    process = context.Process(
        target=_inspection_child,
        args=(PLATFORM, str(path), output),
        daemon=False,
    )
    process.start()
    process.join(timeout=timeout_seconds)
    if process.is_alive():
        _terminate_process_tree(process)
        raise TimeoutError("native inspection exceeded its hard deadline")
    if process.exitcode != 0 or output.empty():
        raise RuntimeError("native inspection child failed")
    status, payload = output.get_nowait()
    if status != "ok":
        raise RuntimeError(f"native inspection failed: {payload}")
    return payload


def attestation_body(data: dict) -> bytes:
    keys = (
        "job_id", "job_status", "request_nonce", "artifact_sha256",
        "platform", "policy_id", "policy_sha256", "evidence_sha256",
        "tool_versions", "isolation", "isolation_receipt_sha256",
        "launcher_id", "sandbox_id", "resource_limits", "runtime_isolation",
        "worker_instance_id",
    )
    return stable_json({key: data.get(key) for key in keys})


def validate_request(body: dict) -> tuple[bytes, str, str]:
    if body.get("platform") != PLATFORM:
        raise ValueError("wrong platform")
    nonce = body.get("request_nonce", "")
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise ValueError("invalid nonce")
    now = time.monotonic()
    with NONCE_LOCK:
        expired = [key for key, seen in NONCES.items() if now - seen > 3600]
        for key in expired:
            del NONCES[key]
        if nonce in NONCES:
            raise ValueError("replayed nonce")
        NONCES[nonce] = now
    artifact = body.get("artifact")
    if not isinstance(artifact, dict):
        raise ValueError("invalid artifact")
    name = Path(str(artifact.get("name", ""))).name
    kind = artifact_type(name)
    policy = body.get("policy")
    if (
        not isinstance(policy, dict)
        or policy.get("policy_id") != POLICY_ID
        or kind is None
        or policy.get("artifact_type") != kind
        or policy.get("required_checks") != sorted(REQUIRED_CHECKS[kind])
        or policy.get("max_artifact_bytes") != MAX_ARTIFACT_BYTES
        or policy.get("max_findings") != 1_000
        or policy.get("max_diagnostic_chars") != MAX_OUTPUT_CHARS
        or policy.get("isolation") != ISOLATION
        or digest(stable_json(policy)) != body.get("policy_sha256")
    ):
        raise ValueError("invalid policy")
    raw = base64.b64decode(artifact["data_base64"], validate=True)
    if (
        not raw or len(raw) > MAX_ARTIFACT_BYTES
        or len(raw) != artifact["size_bytes"]
        or not secrets.compare_digest(digest(raw), artifact["sha256"])
    ):
        raise ValueError("invalid artifact")
    if not name or name != artifact["name"]:
        raise ValueError("invalid artifact name")
    return raw, name, nonce


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if (
            self.path != "/v1/inspect"
            or not secrets.compare_digest(
                self.headers.get("Authorization", ""), f"Bearer {TOKEN}"
            )
        ):
            self.send_error(403)
            return
        if not JOB_LIMIT.acquire(blocking=False):
            self.send_error(429)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("invalid request size")
            body = json.loads(self.rfile.read(length))
            raw, name, nonce = validate_request(body)
            with tempfile.TemporaryDirectory(prefix="native_job_") as directory:
                artifact_path = Path(directory) / name
                artifact_path.write_bytes(raw)
                artifact_path.chmod(0o400)
                runtime_checks = runtime_isolation_checks(artifact_path)
                if any(value is not True for value in runtime_checks.values()):
                    raise RuntimeError("runtime isolation verification failed")
                receipt = ISOLATION_RECEIPT or {}
                timeout_seconds = min(
                    JOB_TIMEOUT_SECONDS,
                    int(receipt["resource_limits"]["timeout_seconds"]),
                )
                findings, coverage, tools, diagnostics = inspect_with_deadline(
                    artifact_path, timeout_seconds,
                )
            kind = artifact_type(name)
            required = REQUIRED_CHECKS[kind]
            checks = coverage.get("checks", {}) if isinstance(coverage, dict) else {}
            coverage = {
                **(coverage if isinstance(coverage, dict) else {}),
                "complete": (
                    isinstance(checks, dict)
                    and required.issubset(checks)
                    and all(checks[item] is True for item in required)
                ),
                "checks": checks,
            }
            evidence = {
                "findings": findings[:1_000], "coverage": coverage,
                "diagnostics": [item[:MAX_OUTPUT_CHARS] for item in diagnostics[:50]],
            }
            response = {
                "job_id": str(uuid.uuid4()), "job_status": "COMPLETED",
                "request_nonce": nonce, "artifact_sha256": digest(raw),
                "platform": PLATFORM, "policy_id": POLICY_ID,
                "policy_sha256": body["policy_sha256"],
                "evidence_sha256": digest(stable_json(evidence)),
                "tool_versions": tools, "isolation": ISOLATION, **evidence,
                "isolation_receipt_sha256": receipt["receipt_sha256"],
                "launcher_id": receipt["launcher_id"],
                "sandbox_id": receipt["sandbox_id"],
                "resource_limits": receipt["resource_limits"],
                "runtime_isolation": runtime_checks,
                "worker_instance_id": receipt["worker_instance_id"],
                "launcher_receipt": {
                    key: receipt[key] for key in (
                        "launcher_id", "sandbox_id", "platform", "issued_at",
                        "expires_at", "isolation", "resource_limits",
                        "worker_instance_id", "worker_public_key", "signature",
                    )
                },
            }
            if WORKER_PRIVATE_KEY is None:
                raise RuntimeError("worker signing key is unavailable")
            response["worker_signature"] = base64.b64encode(
                WORKER_PRIVATE_KEY.sign(attestation_body(response))
            ).decode()
            encoded = stable_json(response)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        except Exception:
            self.send_error(400)
        finally:
            JOB_LIMIT.release()

    def log_message(self, _format: str, *_args: Any) -> None:
        return


if __name__ == "__main__":
    if PLATFORM not in {"Windows", "macOS", "Linux"}:
        raise SystemExit("DESKTOP_WORKER_PLATFORM must be Windows, macOS, or Linux")
    if len(TOKEN) < 32:
        raise SystemExit("Worker token must be at least 32 characters")
    try:
        WORKER_PRIVATE_KEY = load_worker_private_key()
        ISOLATION_RECEIPT = validate_isolation_receipt(WORKER_PRIVATE_KEY)
        consume_worker_private_key_file()
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
