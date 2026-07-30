"""Fail-closed, multi-stage scanning for untrusted uploaded applications."""

from __future__ import annotations

import ast
import ipaddress
import json
import socket
import ssl
import os
import plistlib
import posixpath
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
import logging
import stat
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Callable, Literal
from urllib.parse import urljoin, urlsplit

import anthropic
import httpx
import yaml
from pydantic import (
    BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator,
)

try:
    from .agents.security import SEMGREP_CONFIGS, _semgrep_bin
    from .language_security_controls import detected_languages, language_controls_prompt
    from .scan_models import ScanVerdict, ScannerResult, ScannerStatus, determine_verdict
    from .security_controls import PRODUCT_CONTROLS, VerificationMode, controls_prompt
    from .desktop_sandbox import inspect_native_artifact
    from .upload_limits import (
        MAX_ARCHIVE_UPLOAD_BYTES,
        MAX_CLAUDE_FILE_BYTES,
        MAX_EXTRACTED_BYTES,
        MAX_SOURCE_UPLOAD_BYTES,
        MAX_SYNTAX_FILE_BYTES,
        ensure_scratch_directory,
    )
    from .web_evidence import (
        RedirectEvidence,
        TlsEvidence,
        WebFetchResult,
        cookie_evidence,
        evaluate_passive_policy,
        redact_url,
        sanitize_headers,
    )
except ImportError:  # Support direct imports from crucible/.
    from agents.security import SEMGREP_CONFIGS, _semgrep_bin
    from language_security_controls import detected_languages, language_controls_prompt
    from scan_models import ScanVerdict, ScannerResult, ScannerStatus, determine_verdict
    from security_controls import PRODUCT_CONTROLS, VerificationMode, controls_prompt
    from desktop_sandbox import inspect_native_artifact
    from upload_limits import (
        MAX_ARCHIVE_UPLOAD_BYTES,
        MAX_CLAUDE_FILE_BYTES,
        MAX_EXTRACTED_BYTES,
        MAX_SOURCE_UPLOAD_BYTES,
        MAX_SYNTAX_FILE_BYTES,
        ensure_scratch_directory,
    )
    from web_evidence import (
        RedirectEvidence,
        TlsEvidence,
        WebFetchResult,
        cookie_evidence,
        evaluate_passive_policy,
        redact_url,
        sanitize_headers,
    )

MAX_FILES = 10_000
MAX_ARCHIVE_ENTRIES = 12_000
MAX_ARCHIVE_PATH_DEPTH = 32
MAX_ARCHIVE_NAME_BYTES = 1_024
MAX_ARCHIVE_MEMBER_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 1_000
MAX_ARCHIVE_PROCESS_SECONDS = 30
MAX_WEB_FETCH_BYTES = 10 * 1024 * 1024
MAX_WEB_REDIRECTS = 3
CLAUDE_CHUNK_CHARS = 60_000
CHUNK_OVERLAP_LINES = 20
MAX_CLAUDE_CHUNKS = max(1, min(32, int(os.environ.get("MAX_CLAUDE_CHUNKS", "4"))))
REVIEW_MODEL = "claude-sonnet-4-6"
IGNORED_PARTS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build",
    "__MACOSX",
}
SCANNABLE_SUFFIXES = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".java", ".go", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".cxx",
    ".h", ".hh", ".hpp", ".hxx", ".json", ".yaml", ".yml", ".toml",
    ".xml", ".html", ".htm", ".css", ".scss", ".sass", ".less", ".vue",
    ".svelte", ".gradle", ".properties", ".config", ".csproj", ".fsproj",
}
SCANNABLE_NAMES = {
    "dockerfile", "requirements.txt", "pyproject.toml", "pipfile", "pipfile.lock",
    "poetry.lock", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "pom.xml", "build.gradle", "settings.gradle",
    "gradle.properties", "composer.json", "composer.lock", "gemfile",
    "gemfile.lock", "cargo.toml", "cargo.lock", "go.mod", "go.sum",
    "packages.lock.json", "docker-compose.yml", "docker-compose.yaml", ".env.example",
}
DESKTOP_ARTIFACT_SUFFIXES = {
    ".exe", ".msi", ".msix", ".dmg", ".pkg", ".appimage", ".deb", ".rpm",
    ".snap",
}
MANIFEST_NAMES = {
    "requirements.txt", "poetry.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "pom.xml", "build.gradle", "cargo.lock", "go.mod",
    "packages.lock.json", "composer.lock", "gemfile.lock",
}
SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".java", ".go", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".cxx",
    ".h", ".hh", ".hpp", ".hxx",
}
SEMGREP_SUFFIXES = SOURCE_SUFFIXES | {".json", ".yaml", ".yml", ".xml", ".properties"}
RISK_TERMS = {
    "auth": 10, "login": 10, "permission": 10, "admin": 10, "middleware": 9,
    "route": 8, "controller": 8, "database": 9, "query": 9, "upload": 9,
    "deserialize": 9, "crypto": 8, "secret": 10, "token": 10, "session": 10,
    "request": 7, "network": 7, "config": 7, "docker": 7, "test": 2,
}
CATEGORY_ALIASES = {
    "double deletion": "DOUBLE_FREE", "double free": "DOUBLE_FREE",
    "use after free": "USE_AFTER_FREE", "unsafe reflection": "UNSAFE_REFLECTION",
    "uninitialized variable": "UNINITIALIZED_MEMORY",
}
logger = logging.getLogger(__name__)
REQUIRED_TOOLS = {
    "semgrep": ["semgrep", "--version"],
    "osv-scanner": ["osv-scanner", "--version"],
    "clamscan": ["clamscan", "--version"],
}


def _runtime_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    if not raw.isdigit():
        return default
    return min(max(int(raw), minimum), maximum)


def _resolve_tool(name: str) -> str | None:
    """Find a scanner on PATH or beside the active virtualenv interpreter."""
    found = shutil.which(name)
    if found:
        return found
    candidate = Path(sys.executable).parent / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def _semgrep_environment(runtime_dir: Path) -> dict[str, str]:
    """Keep Semgrep state inside scan scratch and provide an explicit CA bundle."""
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "SEMGREP_LOG_FILE": str(runtime_dir / "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": str(runtime_dir / "settings.yml"),
        "SEMGREP_SEND_METRICS": "off",
    })
    verify_paths = ssl.get_default_verify_paths()
    if "SSL_CERT_FILE" not in environment and verify_paths.cafile:
        environment["SSL_CERT_FILE"] = verify_paths.cafile
    return environment


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)


class ControlOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_VERIFIED = "NOT_VERIFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class ClaudeFinding(StrictModel):
    title: str = Field(min_length=1)
    vulnerability_type: str = Field(min_length=1)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    confidence: float = Field(ge=0, le=1)
    evidence: str = Field(min_length=1)
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    product_control_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    recommendation: str = ""
    status: Literal["FINDING", "REVIEW_REQUIRED", "NOT_VERIFIED"] = "FINDING"

    @field_validator("product_control_ids")
    @classmethod
    def unique_control_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("Duplicate product control IDs")
        return values

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def normalize_cwe_ids(cls, values):
        if not isinstance(values, list):
            return values
        normalized = []
        for value in values:
            if isinstance(value, int) and not isinstance(value, bool):
                normalized.append(f"CWE-{value}")
            elif isinstance(value, str):
                normalized.append(value)
            else:
                normalized.append(value)
        return normalized


class ControlAssessment(StrictModel):
    control_id: str
    outcome: ControlOutcome
    evidence: list[str]
    rationale: str
    confidence: float = Field(ge=0, le=1)


class ClaudeReview(StrictModel):
    findings: list[ClaudeFinding]
    control_assessments: list[ControlAssessment] = Field(default_factory=list)
    analyzed_files: list[str]
    omitted_files: list[str]
    analysis_complete: bool

    @model_validator(mode="after")
    def coverage_consistent(self):
        if self.analysis_complete and self.omitted_files:
            raise ValueError("analysis_complete cannot be true with omitted_files")
        return self


class FileCoverage(StrictModel):
    path: str
    original_characters: int
    included_characters: int
    complete: bool
    omission_reason: str | None = None
    chunks_total: int = 1
    chunks_analyzed: int = 0


@dataclass
class UploadScanResult:
    verdict: ScanVerdict
    reason: str
    scanner_results: list[ScannerResult] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def accepted(self) -> bool:
        return self.verdict == ScanVerdict.PASSED

    @property
    def findings(self) -> list[dict]:
        return [finding for result in self.scanner_results for finding in result.findings]


def check_scanner_readiness() -> dict[str, dict]:
    readiness: dict[str, dict] = {}
    for name, command in REQUIRED_TOOLS.items():
        binary = _resolve_tool(command[0])
        if not binary:
            readiness[name] = {"available": False, "version": "", "error": "NOT_INSTALLED"}
            continue
        try:
            version = _tool_version(binary)
            with tempfile.TemporaryDirectory(prefix="crucible_readiness_") as directory:
                root = Path(directory)
                if name == "semgrep":
                    sample = root / "sample.py"
                    sample.write_text("value = 1\n", encoding="utf-8")
                    smoke_command = [
                        binary, "--config", "p/default", "--json", "--quiet", str(sample),
                    ]
                    accepted_codes = {0, 1}
                elif name == "osv-scanner":
                    (root / "package-lock.json").write_text(
                        json.dumps({
                            "name": "crucible-readiness",
                            "version": "1.0.0",
                            "lockfileVersion": 3,
                            "packages": {
                                "": {
                                    "name": "crucible-readiness",
                                    "version": "1.0.0",
                                    "dependencies": {"is-number": "7.0.0"},
                                },
                                "node_modules/is-number": {
                                    "version": "7.0.0",
                                },
                            },
                        }),
                        encoding="utf-8",
                    )
                    smoke_command = [
                        binary, "--recursive", "--format", "json", str(root),
                    ]
                    accepted_codes = {0, 1}
                else:
                    sample = root / "sample.txt"
                    sample.write_text("scanner readiness\n", encoding="utf-8")
                    smoke_command = [binary, "--no-summary", str(sample)]
                    accepted_codes = {0}
                completed = subprocess.run(
                    smoke_command, capture_output=True, text=True,
                    timeout=30, check=False,
                    env=(
                        _semgrep_environment(root / "semgrep-runtime")
                        if name == "semgrep" else None
                    ),
                )
            readiness[name] = {
                "available": completed.returncode in accepted_codes,
                "version": version,
                "error": (
                    None if completed.returncode in accepted_codes
                    else "FUNCTIONAL_READINESS_FAILED"
                ),
            }
        except Exception:
            logger.exception("Scanner readiness check failed for %s", name)
            readiness[name] = {"available": False, "version": "", "error": "READINESS_EXCEPTION"}
    return readiness


def _tool_version(binary: str, argument: str = "--version") -> str:
    try:
        with tempfile.TemporaryDirectory(prefix="crucible_version_") as directory:
            environment = (
                _semgrep_environment(Path(directory))
                if Path(binary).name in {"semgrep", "pysemgrep"}
                else None
            )
            completed = subprocess.run(
                [binary, argument], capture_output=True, text=True, timeout=10,
                check=False, env=environment,
            )
        return (completed.stdout or completed.stderr).strip().splitlines()[0]
    except Exception:
        return "UNKNOWN"


def safely_run_stage(scanner_name: str, operation: Callable[[], ScannerResult]) -> ScannerResult:
    try:
        result = operation()
        if not isinstance(result, ScannerResult):
            raise TypeError("invalid scanner result")
        return result
    except Exception:
        logger.exception("Unexpected %s stage failure", scanner_name)
        return ScannerResult(
            scanner_name, ScannerStatus.FAILED,
            errors=[f"Unexpected {scanner_name} failure", "STAGE_EXECUTION_FAILED"],
        )


def _is_safe_member(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts


def _inspect_zip_members(members: list[zipfile.ZipInfo]) -> None:
    if len(members) > MAX_ARCHIVE_ENTRIES:
        raise ValueError(
            f"Archive contains more than {MAX_ARCHIVE_ENTRIES:,} total entries."
        )
    normalized: set[str] = set()
    for member in members:
        if member.flag_bits & 0x1:
            raise ValueError("Encrypted ZIP entries are not supported.")
        path = PurePosixPath(member.filename.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Archive traversal detected.")
        if len(member.filename.encode("utf-8", errors="surrogatepass")) > MAX_ARCHIVE_NAME_BYTES:
            raise ValueError("Archive contains an overlong member name.")
        if len(path.parts) > MAX_ARCHIVE_PATH_DEPTH:
            raise ValueError("Archive member path is too deeply nested.")
        if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ValueError("Archive contains an oversized member.")
        if (
            member.file_size > 0
            and member.compress_size == 0
        ):
            raise ValueError("Archive member has an invalid compression ratio.")
        if (
            member.compress_size > 0
            and member.file_size / member.compress_size
            > MAX_ARCHIVE_COMPRESSION_RATIO
        ):
            raise ValueError("Archive member compression ratio exceeds the limit.")
        collision_key = "/".join(path.parts).casefold()
        if collision_key in normalized:
            raise ValueError("Archive contains duplicate or case-colliding paths.")
        normalized.add(collision_key)
        mode = member.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
            raise ValueError("Archive contains a special device entry.")


def _extractable_zip_members(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
) -> list[zipfile.ZipInfo]:
    """Validate internal symlinks but materialize regular files only."""
    extractable = []
    for member in members:
        mode = member.external_attr >> 16
        if not stat.S_ISLNK(mode):
            extractable.append(member)
            continue
        if member.file_size > 4_096:
            raise ValueError("Archive symlink target is too large.")
        try:
            target = archive.read(member).decode("utf-8")
        except (UnicodeDecodeError, RuntimeError) as exc:
            raise ValueError("Archive symlink target is invalid.") from exc
        member_path = PurePosixPath(member.filename.replace("\\", "/"))
        if PurePosixPath(target).is_absolute():
            raise ValueError("Archive symlink escapes the application bundle.")
        resolved = posixpath.normpath(
            posixpath.join(member_path.parent.as_posix(), target)
        )
        if resolved == ".." or resolved.startswith("../"):
            raise ValueError("Archive symlink escapes the application bundle.")
        # Symlinks are intentionally not created. Their real in-bundle targets
        # remain available for static and malware inspection.
    return extractable


def _extract_zip_bounded(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    destination: Path,
) -> None:
    """Stream regular members with byte and wall-clock limits; never make links."""
    started = time.monotonic()
    written = 0
    declared_total = sum(item.file_size for item in members)
    for member in _extractable_zip_members(archive, members):
        if member.is_dir():
            continue
        if time.monotonic() - started > MAX_ARCHIVE_PROCESS_SECONDS:
            raise ValueError("Archive extraction exceeded the time limit.")
        relative = PurePosixPath(member.filename.replace("\\", "/"))
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with archive.open(member) as source, target.open("xb") as output:
                while True:
                    if time.monotonic() - started > MAX_ARCHIVE_PROCESS_SECONDS:
                        raise ValueError("Archive extraction exceeded the time limit.")
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if (
                        written > MAX_EXTRACTED_BYTES
                        or written > declared_total
                    ):
                        raise ValueError("Archive expanded data exceeds declared limits.")
                    output.write(chunk)
        except zipfile.BadZipFile as exc:
            raise ValueError("Archive failed its CRC integrity check.") from exc
        mode = (member.external_attr >> 16) & 0o777
        if mode:
            target.chmod(mode)


def _extract_upload(data: bytes, filename: str, destination: Path) -> list[Path]:
    is_archive = filename.lower().endswith(".zip")
    upload_limit = (
        MAX_ARCHIVE_UPLOAD_BYTES if is_archive else MAX_SOURCE_UPLOAD_BYTES
    )
    if len(data) > upload_limit:
        limit_mb = upload_limit // (1024 * 1024)
        upload_type = "ZIP archive" if is_archive else "source file"
        raise ValueError(f"{upload_type} exceeds the {limit_mb} MB limit.")
    app_dir = destination / "app"
    app_dir.mkdir()
    if is_archive:
        archive_path = destination / "upload.zip"
        archive_path.write_bytes(data)
        try:
            with zipfile.ZipFile(archive_path) as archive:
                all_members = archive.infolist()
                members = [member for member in all_members if not member.is_dir()]
                if len(members) > MAX_FILES:
                    raise ValueError(f"Archive contains more than {MAX_FILES:,} files.")
                if sum(member.file_size for member in members) > MAX_EXTRACTED_BYTES:
                    limit_mb = MAX_EXTRACTED_BYTES // (1024 * 1024)
                    raise ValueError(
                        f"Expanded archive exceeds the {limit_mb} MB limit."
                    )
                _inspect_zip_members(all_members)
                _extract_zip_bounded(archive, all_members, app_dir)
        except (zipfile.BadZipFile, RuntimeError, EOFError, OSError, PermissionError) as exc:
            raise ValueError("The ZIP archive could not be safely extracted.") from exc
    else:
        safe_name = Path(filename).name
        if not safe_name:
            raise ValueError("The uploaded file has no valid name.")
        (app_dir / safe_name).write_bytes(data)
    files = [
        path for path in app_dir.rglob("*")
        if path.is_file()
        and not any(part in IGNORED_PARTS for part in path.parts)
        and (path.suffix.lower() in SCANNABLE_SUFFIXES or path.name.lower() in SCANNABLE_NAMES)
    ]
    if not files:
        packaged_artifacts = [
            path for path in app_dir.rglob("*")
            if (
                (path.is_dir() and path.suffix.lower() == ".app")
                or (
                    path.is_file()
                    and path.suffix.lower() in DESKTOP_ARTIFACT_SUFFIXES
                )
            )
        ]
        if not packaged_artifacts:
            raise ValueError("No supported source or application artifacts were found.")
    return files


def _run_parser(command: list[str], path: Path, timeout: int = 15) -> str | None:
    binary = _resolve_tool(command[0])
    if not binary:
        return f"{command[0]} is not installed"
    try:
        completed = subprocess.run(
            [binary, *command[1:], str(path)], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return f"{command[0]} validation timed out"
    if completed.returncode:
        return (completed.stderr or completed.stdout or "validation failed")[-1000:]
    return None


def _validate_syntax(files: list[Path], root: Path) -> ScannerResult:
    errors: list[str] = []
    unvalidated_source: list[str] = []
    source_validated: list[str] = []
    config_validated: list[str] = []
    not_syntax_applicable: list[str] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.stat().st_size > MAX_SYNTAX_FILE_BYTES:
            unvalidated_source.append(relative)
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"{relative}: not valid UTF-8 text")
            continue
        suffix = path.suffix.lower()
        try:
            if suffix == ".py":
                ast.parse(content, filename=relative)
                source_validated.append(relative)
            elif suffix == ".json":
                json.loads(content)
                config_validated.append(relative)
            elif suffix in {".yaml", ".yml"}:
                yaml.safe_load(content)
                config_validated.append(relative)
            elif suffix == ".xml" or path.name.lower() == "pom.xml":
                ET.fromstring(content)
                config_validated.append(relative)
            elif suffix in {".js", ".mjs", ".cjs"}:
                error = _run_parser(["node", "--check"], path)
                if error:
                    (unvalidated_source if "not installed" in error else errors).append(f"{relative}: {error}")
                else:
                    source_validated.append(relative)
            elif suffix == ".java":
                with tempfile.TemporaryDirectory(prefix="crucible_javac_") as output:
                    error = _run_parser(
                        ["javac", "-proc:none", "-Xlint:none", "-d", output], path
                    )
                if error:
                    if "not installed" in error or "cannot find symbol" in error or "package " in error:
                        unvalidated_source.append(relative)
                    else:
                        errors.append(f"{relative}: {error}")
                else:
                    source_validated.append(relative)
            elif suffix == ".c":
                error = _run_parser(["clang", "-fsyntax-only", "-Wno-everything"], path)
                if error:
                    (unvalidated_source if "file not found" in error or "not installed" in error else errors).append(f"{relative}: {error}")
                else:
                    source_validated.append(relative)
            elif suffix in {".cc", ".cpp", ".cxx"}:
                error = _run_parser(["clang++", "-fsyntax-only", "-Wno-everything"], path)
                if error:
                    (unvalidated_source if "file not found" in error or "not installed" in error else errors).append(f"{relative}: {error}")
                else:
                    source_validated.append(relative)
            elif suffix in {".h", ".hh", ".hpp", ".hxx"}:
                # Headers are not standalone translation units: they may require
                # build flags, generated macros, or a C++ including context.
                command = "clang++" if suffix != ".h" else "clang"
                error = _run_parser(
                    [command, "-fsyntax-only", "-Wno-everything"], path
                )
                if error:
                    unvalidated_source.append(relative)
                else:
                    source_validated.append(relative)
            elif suffix in SOURCE_SUFFIXES:
                unvalidated_source.append(relative)
            else:
                not_syntax_applicable.append(relative)
        except (SyntaxError, ValueError, json.JSONDecodeError, yaml.YAMLError, ET.ParseError) as exc:
            errors.append(f"{relative}: {exc}")
    status = ScannerStatus.FAILED if errors else (
        ScannerStatus.PARTIAL if unvalidated_source else ScannerStatus.SUCCESS
    )
    return ScannerResult(
        "syntax", status, errors=errors,
        metadata={
            "files_total": len(files),
            "source_validated": source_validated,
            "source_unvalidated": unvalidated_source,
            "config_validated": config_validated,
            "not_syntax_applicable": not_syntax_applicable,
        },
    )


def _normalize_semgrep(finding: dict) -> dict:
    raw = str(finding.get("extra", {}).get("severity", "INFO")).upper()
    severity = {"ERROR": "CRITICAL", "WARNING": "MEDIUM"}.get(raw, raw)
    return {
        "title": finding.get("check_id", "Semgrep finding"),
        "vulnerability_type": finding.get("check_id", "STATIC_ANALYSIS"),
        "severity": severity,
        "confidence": 1.0,
        "evidence": finding.get("extra", {}).get("message", ""),
        "file_path": finding.get("path"),
        "line_number": finding.get("start", {}).get("line"),
        "product_control_ids": [],
        "cwe_ids": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
        "source": "semgrep", "mapped": False, "status": "FINDING",
        "recommendation": "",
    }


def _run_semgrep(root: Path, files: list[Path]) -> ScannerResult:
    semgrep = _resolve_tool(_semgrep_bin())
    if not semgrep:
        return ScannerResult("semgrep", ScannerStatus.FAILED, errors=["Semgrep is not installed"])
    args = [semgrep]
    for config in SEMGREP_CONFIGS:
        args.extend(["--config", config])
    args.extend([
        "--json", "--quiet",
        "--exclude", "__MACOSX/**",
        "--exclude", "**/._*",
        str(root),
    ])
    started = time.monotonic()
    timeout_seconds = _runtime_int(
        "SEMGREP_TIMEOUT_SECONDS", default=180, minimum=30, maximum=600
    )
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=_semgrep_environment(root.parent / "semgrep-runtime"),
        )
    except subprocess.TimeoutExpired:
        return ScannerResult(
            "semgrep",
            ScannerStatus.FAILED,
            errors=[f"Semgrep timed out after {timeout_seconds} seconds"],
            metadata={"timeout_seconds": timeout_seconds},
        )
    if completed.returncode not in {0, 1}:
        diagnostic = (completed.stderr or completed.stdout or "No diagnostic output")[-4000:]
        return ScannerResult(
            "semgrep", ScannerStatus.FAILED,
            errors=[f"Semgrep exited with code {completed.returncode}", diagnostic],
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return ScannerResult("semgrep", ScannerStatus.FAILED, errors=["Semgrep returned invalid JSON"])
    findings = [_normalize_semgrep(item) for item in payload.get("results", [])]
    scan_errors = [str(error) for error in payload.get("errors", [])]
    expected = {
        path.resolve().as_posix() for path in files
        if path.suffix.lower() in SEMGREP_SUFFIXES
    }
    path_metadata = payload.get("paths", {})
    observed_raw = path_metadata.get("scanned")
    observed = set()
    for reported in observed_raw or []:
        reported_path = Path(reported)
        if reported_path.is_absolute():
            observed.add(reported_path.resolve().as_posix())
            continue
        candidates = [
            (Path.cwd() / reported_path).resolve(),
            (root / reported_path).resolve(),
        ]
        matched = next(
            (candidate for candidate in candidates if candidate.as_posix() in expected),
            next((candidate for candidate in candidates if candidate.exists()), candidates[0]),
        )
        observed.add(matched.as_posix())
    coverage_known = isinstance(observed_raw, list)
    missing = sorted(expected - observed) if coverage_known else sorted(expected)
    status = (
        ScannerStatus.PARTIAL
        if scan_errors or not coverage_known or missing
        else ScannerStatus.SUCCESS
    )
    time_metadata = payload.get("time", {})
    rules_loaded = len(time_metadata.get("rules", [])) if isinstance(time_metadata, dict) else None
    return ScannerResult(
        "semgrep", status, findings, scan_errors,
        {
            "candidate_files": len(expected),
            "files_reported_scanned": len(observed),
            "files_missing_from_observed": missing,
            "files_skipped": path_metadata.get("skipped", []),
            "rules_loaded": rules_loaded,
            "coverage_confidence": "EXACT" if coverage_known else "LIMITED",
            "coverage_note": (
                "Compared expected files with Semgrep paths.scanned."
                if coverage_known else "Semgrep did not report exact parsed-file coverage."
            ),
            "duration_seconds": round(time.monotonic() - started, 2),
            "version": _tool_version(semgrep),
        },
    )


def _risk_score(path: Path) -> int:
    lowered = path.as_posix().lower()
    return max((score for term, score in RISK_TERMS.items() if term in lowered), default=5)


def _split_file_chunks(relative: str, content: str) -> list[str]:
    lines = content.splitlines(keepends=True)
    if not lines:
        return [f"===== FILE: {relative} | CHUNK 1 OF 1 | LINES 1-1 =====\n"]
    groups: list[tuple[int, int, str]] = []
    start = 0
    while start < len(lines):
        end, size = start, 0
        while end < len(lines) and size + len(lines[end]) <= CLAUDE_CHUNK_CHARS - 200:
            size += len(lines[end])
            end += 1
        if end == start:
            end += 1
        groups.append((start, end, "".join(lines[start:end])))
        if end >= len(lines):
            break
        start = max(start + 1, end - CHUNK_OVERLAP_LINES)
    total = len(groups)
    return [
        f"===== FILE: {relative} | CHUNK {index} OF {total} | "
        f"LINES {start + 1}-{end} =====\n{text}\n"
        for index, (start, end, text) in enumerate(groups, 1)
    ]


def _claude_chunks(
    files: list[Path], root: Path,
) -> tuple[list[tuple[str, list[str]]], list[str], list[FileCoverage]]:
    chunks: list[tuple[str, list[str]]] = []
    omitted: set[str] = set()
    coverage: list[FileCoverage] = []
    for path in sorted(files, key=lambda item: (-_risk_score(item), item.as_posix())):
        relative = path.relative_to(root).as_posix()
        file_size = path.stat().st_size
        if file_size > MAX_CLAUDE_FILE_BYTES:
            omitted.add(relative)
            coverage.append(FileCoverage(
                path=relative,
                original_characters=file_size,
                included_characters=0,
                complete=False,
                omission_reason="FILE_SIZE_LIMIT",
                chunks_total=1,
                chunks_analyzed=0,
            ))
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            omitted.add(relative)
            coverage.append(FileCoverage(
                path=relative, original_characters=0, included_characters=0,
                complete=False, omission_reason="NON_UTF8",
            ))
            continue
        blocks = _split_file_chunks(relative, content)
        available = max(0, MAX_CLAUDE_CHUNKS - len(chunks))
        selected = blocks[:available]
        chunks.extend((block, [relative]) for block in selected)
        included_chars = sum(len(block) for block in selected)
        complete = len(selected) == len(blocks)
        if not complete:
            omitted.add(relative)
        coverage.append(FileCoverage(
            path=relative,
            original_characters=len(content),
            included_characters=min(len(content), included_chars),
            complete=complete,
            omission_reason=None if complete else "GLOBAL_CHUNK_LIMIT",
            chunks_total=len(blocks),
            chunks_analyzed=0,
        ))
    return chunks, sorted(omitted), coverage


def _normalize_claude_finding(item: ClaudeFinding) -> dict:
    vulnerability = CATEGORY_ALIASES.get(
        item.vulnerability_type.lower().replace("_", " "), item.vulnerability_type.upper()
    )
    valid_ids = [control_id for control_id in item.product_control_ids if control_id in PRODUCT_CONTROLS]
    invalid_ids = [control_id for control_id in item.product_control_ids if control_id not in PRODUCT_CONTROLS]
    mapped = bool(valid_ids)
    return {
        **item.model_dump(),
        "product_control_ids": valid_ids,
        "invalid_product_control_ids": invalid_ids,
        "vulnerability_type": vulnerability,
        "source": "claude", "mapped": mapped,
        "original_category": None if mapped else item.vulnerability_type,
        "requires_mapping_review": not mapped,
        "mapping_status": "INVALID" if invalid_ids else ("MAPPED" if mapped else "UNMAPPED"),
    }


def _determine_claude_status(
    model_incomplete: bool,
    local_omitted_files: list[str],
    file_coverage: list[FileCoverage],
) -> ScannerStatus:
    if (
        model_incomplete
        or local_omitted_files
        or any(
            not item.complete or item.chunks_analyzed != item.chunks_total
            for item in file_coverage
        )
    ):
        return ScannerStatus.PARTIAL
    return ScannerStatus.SUCCESS


def _claude_validation_feedback(exc: Exception) -> str:
    """Return model-safe schema feedback without echoing source or response content."""
    if isinstance(exc, ValidationError):
        errors = exc.errors(include_url=False, include_input=False)
        details = []
        for error in errors[:12]:
            location = ".".join(str(part) for part in error.get("loc", ())) or "response"
            details.append(f"{location}: {error.get('type', 'invalid')}")
        return "; ".join(details) or "response: schema_validation_failed"
    if isinstance(exc, IndexError):
        return "response.content: missing_text_block"
    return "response: invalid_or_truncated_json"


def _run_claude(files: list[Path], root: Path) -> ScannerResult:
    if not files:
        return ScannerResult(
            "claude",
            ScannerStatus.SKIPPED,
            errors=["No reviewable source was present in the packaged artifact"],
            metadata={"files_total": 0, "not_applicable": True},
        )
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return ScannerResult("claude", ScannerStatus.FAILED, errors=["Anthropic API key is not configured"])
    chunks, omitted, file_coverage = _claude_chunks(files, root)
    timeout_seconds = _runtime_int(
        "CLAUDE_REVIEW_TIMEOUT_SECONDS", default=120, minimum=30, maximum=300
    )
    max_retries = _runtime_int(
        "CLAUDE_REVIEW_MAX_RETRIES", default=2, minimum=0, maximum=3
    )
    max_output_tokens = _runtime_int(
        "CLAUDE_REVIEW_MAX_OUTPUT_TOKENS",
        default=16_384,
        minimum=4_096,
        maximum=32_768,
    )
    client = anthropic.Anthropic(api_key=api_key, max_retries=0)
    languages = detected_languages({path.suffix.lower() for path in files})
    findings: list[dict] = []
    analyzed: list[str] = []
    assessment_map: dict[str, ControlAssessment] = {}
    model_incomplete = False
    system = """You are a senior application-security reviewer. Return JSON only and
preserve technical findings even when they do not map to a product control. Never treat
missing evidence as a pass. Use this exact schema:
{"findings":[{"title":"...","vulnerability_type":"...","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","confidence":0.0,"evidence":"...","file_path":"path or null","line_number":1,"product_control_ids":[],"cwe_ids":[],"recommendation":"...","status":"FINDING|REVIEW_REQUIRED|NOT_VERIFIED"}],"control_assessments":[{"control_id":"AUTH-001","outcome":"PASS|FAIL|NOT_APPLICABLE|NOT_VERIFIED|REVIEW_REQUIRED","evidence":[],"rationale":"...","confidence":0.0}],"analyzed_files":[],"omitted_files":[],"analysis_complete":true}
File references must name supplied files. Report concrete vulnerabilities and important
unverified applicable controls. Unknown categories are allowed. Return exactly one
control_assessment only for controls with a FAIL, REVIEW_REQUIRED, or NOT_VERIFIED
outcome; omit PASS and NOT_APPLICABLE controls. Omission is not interpreted as a pass.
For this request, analysis_complete describes only the supplied chunk, and
analyzed_files must list its file path."""
    catalog = controls_prompt() + "\n\n" + language_controls_prompt(languages)
    for source, chunk_files in chunks:
        prompt = f"CATALOGS:\n{catalog}\n\nFILES:\n{source}"
        review = None
        transient_error = ""
        validation_failures: list[str] = []
        request_prompt = prompt
        for attempt in range(max_retries + 1):
            try:
                response = client.messages.create(
                    model=REVIEW_MODEL, max_tokens=max_output_tokens, system=system,
                    messages=[{"role": "user", "content": request_prompt}],
                    timeout=timeout_seconds,
                )
                if getattr(response, "stop_reason", None) == "max_tokens":
                    raise ValueError("truncated")
                block = response.content[0]
                raw = block.text.strip() if block.type == "text" else ""
                raw = (
                    raw.removeprefix("```json")
                    .removeprefix("```")
                    .removesuffix("```")
                    .strip()
                )
                review = ClaudeReview.model_validate_json(raw)
                break
            except (
                anthropic.APITimeoutError,
                anthropic.APIConnectionError,
                anthropic.RateLimitError,
            ) as exc:
                transient_error = type(exc).__name__
                if attempt < max_retries:
                    time.sleep(min(4, 2 ** attempt))
            except anthropic.APIError as exc:
                return ScannerResult(
                    "claude",
                    ScannerStatus.FAILED,
                    findings,
                    [f"Claude request failed: {type(exc).__name__}"],
                    {"attempts": attempt + 1, "timeout_seconds": timeout_seconds},
                )
            except (ValidationError, ValueError, IndexError) as exc:
                feedback = _claude_validation_feedback(exc)
                validation_failures.append(feedback)
                transient_error = "CLAUDE_SCHEMA_VALIDATION_FAILED"
                if attempt < max_retries:
                    request_prompt = (
                        f"{prompt}\n\nCORRECTION REQUIRED: Your previous response did not "
                        "match the required JSON schema. Return a complete replacement JSON "
                        f"object only. Validation issues: {feedback}"
                    )
                    continue
                return ScannerResult(
                    "claude", ScannerStatus.FAILED, findings,
                    [
                        "Claude response did not satisfy the required schema after bounded retries",
                        "CLAUDE_SCHEMA_VALIDATION_FAILED",
                    ],
                    {
                        "attempts": attempt + 1,
                        "timeout_seconds": timeout_seconds,
                        "max_output_tokens": max_output_tokens,
                        "retry_exhausted": True,
                        "validation_failures": validation_failures,
                    },
                )
        if review is None:
            return ScannerResult(
                "claude",
                ScannerStatus.FAILED,
                findings,
                [
                    "Claude review did not complete after bounded retries",
                    transient_error or "CLAUDE_RETRY_EXHAUSTED",
                ],
                {
                    "attempts": max_retries + 1,
                    "timeout_seconds": timeout_seconds,
                    "max_output_tokens": max_output_tokens,
                    "retry_exhausted": True,
                },
            )
        if set(review.analyzed_files) != set(chunk_files):
            return ScannerResult("claude", ScannerStatus.FAILED, findings, ["Claude file coverage does not match the supplied chunk"])
        if review.analysis_complete and review.omitted_files:
            return ScannerResult("claude", ScannerStatus.FAILED, findings, ["Claude coverage fields are inconsistent"])
        if any(
            item.file_path is not None and item.file_path not in chunk_files
            for item in review.findings
        ):
            return ScannerResult("claude", ScannerStatus.FAILED, findings, ["Claude finding references an unknown file"])
        returned_ids = [assessment.control_id for assessment in review.control_assessments]
        if len(returned_ids) != len(set(returned_ids)):
            return ScannerResult("claude", ScannerStatus.FAILED, findings, ["Duplicate control assessments"])
        unknown_ids = sorted(set(returned_ids) - set(PRODUCT_CONTROLS))
        if unknown_ids:
            return ScannerResult(
                "claude", ScannerStatus.FAILED, findings,
                ["Claude returned unknown product control IDs"],
                {"unknown_control_ids": unknown_ids},
            )
        model_incomplete = model_incomplete or not review.analysis_complete or bool(review.omitted_files)
        analyzed.extend(review.analyzed_files)
        findings.extend(_normalize_claude_finding(item) for item in review.findings)
        priority = {
            ControlOutcome.FAIL: 5, ControlOutcome.REVIEW_REQUIRED: 4,
            ControlOutcome.NOT_VERIFIED: 3, ControlOutcome.PASS: 2,
            ControlOutcome.NOT_APPLICABLE: 1,
        }
        for assessment in review.control_assessments:
            control = PRODUCT_CONTROLS[assessment.control_id]
            if (
                assessment.outcome == ControlOutcome.PASS
                and VerificationMode.STATIC not in control.verification_modes
            ):
                assessment.outcome = ControlOutcome.NOT_VERIFIED
                assessment.rationale = "Static source review cannot authoritatively pass this control."
            existing = assessment_map.get(assessment.control_id)
            if existing is None or priority[assessment.outcome] > priority[existing.outcome]:
                assessment_map[assessment.control_id] = assessment
        for item in file_coverage:
            if item.path in chunk_files:
                item.chunks_analyzed += 1
    deduplicated: dict[tuple, dict] = {}
    for finding in findings:
        key = (
            finding.get("vulnerability_type"), finding.get("file_path"),
            finding.get("line_number"), finding.get("title"),
        )
        deduplicated[key] = finding
    findings = list(deduplicated.values())
    for assessment in assessment_map.values():
        control = PRODUCT_CONTROLS[assessment.control_id]
        if VerificationMode.DEDICATED_SCANNER in control.verification_modes:
            continue
        if assessment.outcome in {
            ControlOutcome.FAIL, ControlOutcome.NOT_VERIFIED, ControlOutcome.REVIEW_REQUIRED,
        }:
            findings.append({
                "title": control.name,
                "vulnerability_type": "PRODUCT_CONTROL_ASSESSMENT",
                "severity": "HIGH" if assessment.outcome == ControlOutcome.FAIL else "INFO",
                "confidence": assessment.confidence,
                "evidence": "; ".join(assessment.evidence) or assessment.rationale,
                "file_path": None, "line_number": None,
                "product_control_ids": [assessment.control_id], "cwe_ids": [],
                "recommendation": assessment.rationale, "source": "claude",
                "mapped": True,
                "status": "FINDING" if assessment.outcome == ControlOutcome.FAIL else assessment.outcome.value,
            })
    incomplete_files = [
        item.path for item in file_coverage
        if not item.complete or item.chunks_analyzed != item.chunks_total
    ]
    status = _determine_claude_status(model_incomplete, omitted, file_coverage)
    errors = []
    if omitted:
        errors.append("Repository exceeded Claude analysis capacity")
    if model_incomplete:
        errors.append("Claude reported incomplete analysis")
    return ScannerResult(
        "claude", status, findings,
        errors,
        {
            "languages": languages, "files_total": len(files),
            "files_analyzed": len(set(analyzed)), "omitted_files": omitted,
            "high_priority_files_omitted": sum(_risk_score(root / name) >= 8 for name in omitted),
            "model_reported_incomplete": model_incomplete,
            "incomplete_files": incomplete_files,
            "file_coverage": [item.model_dump() for item in file_coverage],
            "controls_assessed": len(assessment_map),
            "controls_catalog_total": len(PRODUCT_CONTROLS),
            "unreported_controls_are_passed": False,
        },
    )


def _run_dependencies(root: Path, files: list[Path]) -> ScannerResult:
    manifests = [path for path in files if path.name.lower() in MANIFEST_NAMES]
    if not manifests:
        return ScannerResult("dependencies", ScannerStatus.SUCCESS, metadata={"manifests": [], "not_applicable": True})
    osv = _resolve_tool("osv-scanner")
    if not osv:
        return ScannerResult(
            "dependencies", ScannerStatus.FAILED,
            errors=["Dependency manifests found but osv-scanner is not installed"],
            metadata={"manifests": [path.relative_to(root).as_posix() for path in manifests]},
        )
    try:
        completed = subprocess.run(
            [osv, "--recursive", "--format", "json", str(root)],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        return ScannerResult("dependencies", ScannerStatus.FAILED, errors=["Dependency scan timed out"])
    if completed.returncode not in {0, 1}:
        return ScannerResult("dependencies", ScannerStatus.FAILED, errors=[completed.stderr[-4000:]])
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return ScannerResult("dependencies", ScannerStatus.FAILED, errors=["osv-scanner returned invalid JSON"])
    findings = []
    for result in payload.get("results", []):
        for package in result.get("packages", []):
            package_info = package.get("package", {})
            for vulnerability in package.get("vulnerabilities", []):
                findings.append({
                    "title": vulnerability.get("id", "Dependency vulnerability"),
                    "vulnerability_type": "VULNERABLE_DEPENDENCY", "severity": "HIGH",
                    "confidence": 1.0, "evidence": vulnerability.get("summary", ""),
                    "file_path": result.get("source", {}).get("path"),
                    "line_number": None, "product_control_ids": [],
                    "cwe_ids": vulnerability.get("database_specific", {}).get("cwe_ids", []),
                    "source": "osv-scanner", "mapped": True, "status": "FINDING",
                    "package": package_info.get("name"), "version": package_info.get("version"),
                    "recommendation": "Upgrade to a patched dependency version.",
                })
    lockfiles = {
        "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "cargo.lock", "packages.lock.json", "composer.lock", "gemfile.lock",
    }
    has_lockfile = any(path.name.lower() in lockfiles for path in manifests)
    return ScannerResult(
        "dependencies",
        ScannerStatus.SUCCESS if has_lockfile else ScannerStatus.PARTIAL,
        findings,
        [] if has_lockfile else ["No lockfile found; exact resolved versions may be unknown"],
        {
            "manifests": len(manifests),
            "lockfile_detected": has_lockfile,
            "version": _tool_version(osv),
        },
    )


def _run_malware(root: Path, files: list[Path]) -> ScannerResult:
    clamscan = _resolve_tool("clamscan")
    if not clamscan:
        return ScannerResult("malware", ScannerStatus.FAILED, errors=["Malware scan unavailable: ClamAV is not installed"])
    try:
        completed = subprocess.run(
            [clamscan, "--recursive", "--infected", "--no-summary", str(root)],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        return ScannerResult("malware", ScannerStatus.FAILED, errors=["Malware scan timed out"])
    if completed.returncode not in {0, 1}:
        return ScannerResult("malware", ScannerStatus.FAILED, errors=[completed.stderr[-4000:]])
    findings = [
        {
            "title": "Malware detected", "vulnerability_type": "MALWARE",
            "severity": "CRITICAL", "confidence": 1.0, "evidence": line,
            "file_path": line.split(":", 1)[0], "line_number": None,
            "product_control_ids": [], "cwe_ids": [], "source": "clamav",
            "mapped": True, "status": "FINDING",
            "recommendation": "Quarantine the file and investigate its origin.",
        }
        for line in completed.stdout.splitlines() if line.endswith(" FOUND")
    ]
    return ScannerResult(
        "malware", ScannerStatus.SUCCESS, findings,
        metadata={"files_scanned": len(files), "version": _tool_version(clamscan)},
    )


def _run_macos_artifact_inspection(root: Path) -> ScannerResult:
    """Inspect macOS release metadata without launching uploaded executables."""
    bundles = sorted(
        path for path in root.rglob("*.app")
        if (
            path.is_dir()
            and (path / "Contents").is_dir()
            and "__MACOSX" not in path.parts
        )
    )
    if not bundles:
        return ScannerResult(
            "desktop_artifact",
            ScannerStatus.SUCCESS,
            metadata={"not_applicable": True, "platform": None},
        )
    codesign = _resolve_tool("codesign")
    if not codesign:
        return ScannerResult(
            "desktop_artifact",
            ScannerStatus.PARTIAL,
            errors=["macOS code-signing inspection requires a macOS scanner worker"],
            metadata={
                "platform": "macOS",
                "bundles": [path.relative_to(root).as_posix() for path in bundles],
            },
        )

    findings = []
    coverage_errors: list[str] = []
    metadata: dict[str, object] = {"platform": "macOS", "bundles": []}
    for bundle in bundles:
        relative = bundle.relative_to(root).as_posix()
        bundle_metadata: dict[str, object] = {"path": relative}
        info_path = bundle / "Contents" / "Info.plist"
        if info_path.is_file():
            try:
                info = plistlib.loads(info_path.read_bytes())
                if not isinstance(info, dict):
                    raise plistlib.InvalidFileException()
                bundle_metadata.update({
                    "bundle_id": info.get("CFBundleIdentifier"),
                    "version": (
                        info.get("CFBundleShortVersionString")
                        or info.get("CFBundleVersion")
                    ),
                    "executable": info.get("CFBundleExecutable"),
                })
                missing_fields = [
                    key for key in (
                        "CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion"
                    )
                    if not isinstance(info.get(key), str) or not info.get(key).strip()
                ]
                if missing_fields:
                    findings.append({
                        "title": "Required macOS bundle metadata is missing",
                        "vulnerability_type": "MISSING_APP_METADATA",
                        "severity": "HIGH", "confidence": 1.0,
                        "evidence": f"Missing or invalid: {', '.join(missing_fields)}",
                        "file_path": f"{relative}/Contents/Info.plist",
                        "line_number": None, "product_control_ids": [], "cwe_ids": [],
                        "source": "desktop_artifact", "mapped": True,
                        "status": "FINDING",
                        "recommendation": "Provide all required release bundle fields.",
                    })
                executable_name = info.get("CFBundleExecutable")
                if isinstance(executable_name, str) and executable_name.strip():
                    executable_is_name = (
                        executable_name not in {".", ".."}
                        and Path(executable_name).name == executable_name
                        and "/" not in executable_name
                        and "\\" not in executable_name
                    )
                    executable_path = (
                        bundle / "Contents" / "MacOS" / executable_name
                        if executable_is_name else bundle / "Contents" / "MacOS"
                    )
                    executable_ok = (
                        executable_is_name and executable_path.is_file()
                        and bool(executable_path.stat().st_mode & 0o111)
                    )
                    bundle_metadata["executable_present_and_marked_executable"] = (
                        executable_ok
                    )
                    if not executable_ok:
                        findings.append({
                            "title": "macOS bundle executable is missing or not executable",
                            "vulnerability_type": "INVALID_BUNDLE_EXECUTABLE",
                            "severity": "HIGH", "confidence": 1.0,
                            "evidence": executable_path.relative_to(root).as_posix(),
                            "file_path": relative, "line_number": None,
                            "product_control_ids": [], "cwe_ids": [],
                            "source": "desktop_artifact", "mapped": True,
                            "status": "FINDING",
                            "recommendation": (
                                "Include CFBundleExecutable under Contents/MacOS and "
                                "set its executable permission."
                            ),
                        })
            except (plistlib.InvalidFileException, OSError):
                findings.append({
                    "title": "Invalid macOS application metadata",
                    "vulnerability_type": "INVALID_APP_METADATA",
                    "severity": "HIGH", "confidence": 1.0,
                    "evidence": f"{relative}/Contents/Info.plist could not be parsed",
                    "file_path": f"{relative}/Contents/Info.plist",
                    "line_number": None, "product_control_ids": [], "cwe_ids": [],
                    "source": "desktop_artifact", "mapped": True, "status": "FINDING",
                    "recommendation": "Rebuild the bundle with a valid Info.plist.",
                })
        else:
            findings.append({
                "title": "macOS application metadata is missing",
                "vulnerability_type": "MISSING_APP_METADATA",
                "severity": "HIGH", "confidence": 1.0,
                "evidence": f"{relative}/Contents/Info.plist is absent",
                "file_path": relative, "line_number": None,
                "product_control_ids": [], "cwe_ids": [],
                "source": "desktop_artifact", "mapped": True, "status": "FINDING",
                "recommendation": "Include a valid Info.plist in the release bundle.",
            })

        verification = subprocess.run(
            [codesign, "--verify", "--deep", "--strict", "--verbose=2", str(bundle)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        bundle_metadata["signature_valid"] = verification.returncode == 0
        if verification.returncode:
            findings.append({
                "title": "Invalid macOS code signature",
                "vulnerability_type": "INVALID_CODE_SIGNATURE",
                "severity": "HIGH", "confidence": 1.0,
                "evidence": (
                    verification.stderr or verification.stdout
                    or "codesign verification failed"
                )[-2000:],
                "file_path": relative, "line_number": None,
                "product_control_ids": [], "cwe_ids": [],
                "source": "desktop_artifact", "mapped": True, "status": "FINDING",
                "recommendation": (
                    "Sign every nested executable with Developer ID and verify the "
                    "final bundle before distribution."
                ),
            })

        entitlements = subprocess.run(
            [codesign, "-d", "--entitlements", ":-", str(bundle)],
            capture_output=True, timeout=30, check=False,
        )
        raw_entitlements = entitlements.stdout
        parsed_entitlements = {}
        entitlement_status = "verified"
        if entitlements.returncode == 0 and raw_entitlements:
            try:
                parsed_entitlements = plistlib.loads(raw_entitlements)
                if not isinstance(parsed_entitlements, dict):
                    raise plistlib.InvalidFileException()
            except (plistlib.InvalidFileException, ValueError, TypeError):
                entitlement_status = "invalid"
        else:
            entitlement_status = "unavailable"
        bundle_metadata["entitlement_inspection"] = entitlement_status
        if entitlement_status != "verified":
            coverage_errors.append(
                f"{relative}: entitlement inspection {entitlement_status}"
            )
        bundle_metadata["entitlements"] = sorted(parsed_entitlements)
        risky_entitlements = {
            "com.apple.security.get-task-allow": "Debug task attachment is enabled",
            "com.apple.security.cs.disable-library-validation": (
                "Library validation is disabled"
            ),
            "com.apple.security.cs.allow-unsigned-executable-memory": (
                "Unsigned executable memory is allowed"
            ),
            "com.apple.security.cs.disable-executable-page-protection": (
                "Executable-memory protection is disabled"
            ),
        }
        for entitlement, description in risky_entitlements.items():
            if parsed_entitlements.get(entitlement) is True:
                findings.append({
                    "title": description,
                    "vulnerability_type": "RISKY_MACOS_ENTITLEMENT",
                    "severity": "HIGH", "confidence": 1.0,
                    "evidence": entitlement,
                    "file_path": relative, "line_number": None,
                    "product_control_ids": [], "cwe_ids": [],
                    "source": "desktop_artifact", "mapped": True,
                    "status": "FINDING",
                    "recommendation": (
                        "Remove the entitlement unless a documented release "
                        "requirement proves it is necessary."
                    ),
                })
        metadata["bundles"].append(bundle_metadata)
    coverage_errors.append(
        "Notarization, Gatekeeper, hardened runtime, signing identity, certificate "
        "trust, nested entitlement policy, Mach-O structure, and quarantine behavior "
        "require additional attested macOS worker evidence"
    )
    return ScannerResult(
        "desktop_artifact",
        ScannerStatus.PARTIAL,
        findings=findings,
        errors=coverage_errors,
        metadata=metadata,
    )


def _identify_desktop_artifact(path: Path) -> str | None:
    """Identify supported native containers from bounded signature bytes."""
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            head = stream.read(16)
            tail = b""
            if size >= 512:
                stream.seek(-512, os.SEEK_END)
                tail = stream.read(512)
    except OSError:
        return None
    if head.startswith(b"MZ"):
        return ".exe"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return ".msi"
    if head.startswith(b"PK\x03\x04"):
        return ".zip-container"
    if head.startswith(b"!<arch>\n"):
        return ".deb"
    if head.startswith(b"\xed\xab\xee\xdb"):
        return ".rpm"
    if head.startswith(b"hsqs"):
        return ".snap"
    if head.startswith(b"\x7fELF") and head[8:11] in {b"AI\x01", b"AI\x02"}:
        return ".appimage"
    if head.startswith(b"xar!"):
        return ".pkg"
    if len(tail) >= 4 and tail[:4] == b"koly":
        return ".dmg"
    return None


def _package_app_bundle(bundle: Path, destination: Path) -> Path:
    """Create a deterministic, non-compressed worker envelope for one .app."""
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in sorted(bundle.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file():
                continue
            relative = Path(bundle.name) / path.relative_to(bundle)
            info = zipfile.ZipInfo(relative.as_posix())
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
            with path.open("rb") as source, archive.open(info, "w") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    return destination


def _run_desktop_artifact_inspection(root: Path) -> ScannerResult:
    """Route packaged desktop artifacts to the available platform inspector."""
    mac_result = _run_macos_artifact_inspection(root)
    artifacts = sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in DESKTOP_ARTIFACT_SUFFIXES
    )
    if not artifacts and mac_result.metadata.get("not_applicable"):
        return mac_result
    if not artifacts and mac_result.status == ScannerStatus.SUCCESS:
        return mac_result
    platforms = {
        ".exe": "Windows", ".msi": "Windows", ".msix": "Windows",
        ".dmg": "macOS", ".pkg": "macOS",
        ".appimage": "Linux", ".deb": "Linux", ".rpm": "Linux", ".snap": "Linux",
    }
    artifact_records = []
    for path in artifacts:
        suffix = path.suffix.lower()
        identified = _identify_desktop_artifact(path)
        compatible = {
            ".msix": {".zip-container"},
        }.get(suffix, {suffix})
        artifact_records.append({
            "path": path.relative_to(root).as_posix(),
            "claimed_type": suffix,
            "identified_type": identified,
            "content_matches_claim": identified in compatible,
            "platform": platforms[suffix],
        })
    remote_results: list[ScannerResult] = []
    remote_targets: list[tuple[Path, str, str]] = [
        (path, platforms[path.suffix.lower()], path.relative_to(root).as_posix())
        for path in artifacts
    ]
    if os.environ.get("DESKTOP_INSPECTION_MODE", "disabled").lower() == "remote":
        mac_bundles = (
            mac_result.metadata.get("bundles", [])
            if not mac_result.metadata.get("not_applicable") else []
        )
        envelope_root = root.parent / "desktop-worker-envelopes"
        for bundle_item in mac_bundles:
            bundle_relative = (
                bundle_item if isinstance(bundle_item, str)
                else bundle_item.get("path")
            )
            if not isinstance(bundle_relative, str):
                continue
            bundle = root / bundle_relative
            envelope = _package_app_bundle(
                bundle, envelope_root / f"{bundle.name}.zip"
            )
            remote_targets.append((envelope, "macOS", bundle_relative))
        remote_results = [
            inspect_native_artifact(path, platform)
            for path, platform, _display_path in remote_targets
        ]
    detected = sorted({
        *({platforms[path.suffix.lower()] for path in artifacts}),
        *(set() if mac_result.metadata.get("not_applicable") else {"macOS"}),
    })
    errors = [] if mac_result.metadata.get("not_applicable") else list(mac_result.errors)
    if artifacts and not remote_results:
        errors.append(
            "Every packaged artifact requires a platform-specific isolated "
            "inspection worker"
        )
    if (
        any(not record["content_matches_claim"] for record in artifact_records)
        and not all(
            result.status == ScannerStatus.SUCCESS for result in remote_results
        )
    ):
        errors.append(
            "One or more artifact filename extensions could not be confirmed by "
            "content signatures"
        )
    metadata = {
        "platforms": detected,
        "artifacts": artifact_records,
    }
    findings = []
    if not mac_result.metadata.get("not_applicable"):
        metadata["macos"] = mac_result.metadata
        findings.extend(mac_result.findings)
    for (_path, _platform, display_path), remote in zip(
        remote_targets, remote_results
    ):
        findings.extend(remote.findings)
        metadata.setdefault("worker_results", []).append({
            "path": display_path,
            "status": remote.status.value,
            **remote.metadata,
        })
        errors.extend(remote.errors)
    all_workers_complete = (
        bool(remote_targets)
        and len(remote_results) == len(remote_targets)
        and all(
            result.status == ScannerStatus.SUCCESS
            and result.metadata.get("verified_attestation") is True
            for result in remote_results
        )
    )
    status = (
        ScannerStatus.SUCCESS
        if all_workers_complete
        else ScannerStatus.PARTIAL
    )
    if all_workers_complete:
        errors = [
            error for remote in remote_results for error in remote.errors
        ]
    return ScannerResult(
        "desktop_artifact",
        status,
        findings=findings,
        errors=errors,
        metadata=metadata,
    )


ScanProgressCallback = Callable[[int, str], None]


def _resolve_public_web_addresses(url: str) -> tuple[str, ...]:
    """Resolve a bounded HTTPS URL and return only globally routable addresses."""
    if len(url) > 2_048:
        raise ValueError("Web app URL is too long.")
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Enter a public HTTPS web app URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Web app URL must not contain credentials or a fragment.")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("Web app URL contains an invalid port.") from exc
    try:
        answers = socket.getaddrinfo(
            parsed.hostname, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ValueError("Web app hostname could not be resolved.") from exc
    addresses = {answer[4][0] for answer in answers}
    if not addresses or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise ValueError("Web app URL must resolve only to public addresses.")
    return tuple(sorted(addresses))


def _validate_public_web_url(url: str) -> str:
    """Accept only bounded HTTPS URLs whose DNS answers are all public."""
    _resolve_public_web_addresses(url)
    return url


def _fetch_web_app(url: str) -> WebFetchResult:
    """Fetch one public HTML entry page with bounded redirects and response size."""
    requested_url = _validate_public_web_url(url.strip())
    current_url = requested_url
    redirects: list[RedirectEvidence] = []
    egress_proxy = os.environ.get("WEB_EGRESS_PROXY_URL", "").strip()
    if (
        os.environ.get("REQUIRE_WEB_EGRESS_GATEWAY", "false").lower() == "true"
        and not egress_proxy
    ):
        raise ValueError("The required web egress gateway is not configured.")
    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(20.0),
        trust_env=False,
        proxy=egress_proxy or None,
        headers={"User-Agent": "Crucible-Security-Scanner/1.0"},
    ) as client:
        for redirect_count in range(MAX_WEB_REDIRECTS + 1):
            resolved = _resolve_public_web_addresses(current_url)
            with client.stream("GET", current_url) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location or redirect_count == MAX_WEB_REDIRECTS:
                        raise ValueError("Web app redirected too many times.")
                    redirects.append(
                        RedirectEvidence(
                            response.status_code,
                            redact_url(current_url),
                            redact_url(urljoin(current_url, location)),
                        )
                    )
                    current_url = urljoin(current_url, location)
                    continue
                response.raise_for_status()
                content_type = response.headers.get("content-type", "").lower()
                if not (
                    content_type.startswith("text/html")
                    or content_type.startswith("application/xhtml+xml")
                ):
                    raise ValueError("Web app URL did not return an HTML page.")
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_WEB_FETCH_BYTES:
                    raise ValueError("Web app page exceeds the 10 MB fetch limit.")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_WEB_FETCH_BYTES:
                        raise ValueError("Web app page exceeds the 10 MB fetch limit.")
                if not body:
                    raise ValueError("Web app URL returned an empty page.")
                headers, metadata_truncated = sanitize_headers(
                    response.headers.multi_items()
                )
                cookies = cookie_evidence(response.headers.get_list("set-cookie"))
                hostname = urlsplit(current_url).hostname or ""
                return WebFetchResult(
                    body=bytes(body),
                    requested_url=requested_url,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers=headers,
                    cookies=cookies,
                    redirects=tuple(redirects),
                    resolved_ip=resolved[0],
                    tls=TlsEvidence(
                        hostname=hostname,
                        certificate_verified=True,
                        protocol=response.http_version,
                    ),
                    metadata_truncated=metadata_truncated,
                    address_pinned=bool(
                        egress_proxy
                        and os.environ.get(
                            "WEB_EGRESS_GATEWAY_ATTESTED", "false"
                        ).lower() == "true"
                    ),
                )
    raise ValueError("Web app could not be fetched.")


def scan_web_url(
    url: str,
    progress_callback: ScanProgressCallback | None = None,
) -> UploadScanResult:
    """Fetch a public web entry page and scan its delivered HTML without execution."""
    def report(percent: int, message: str) -> None:
        if progress_callback is not None:
            progress_callback(percent, message)

    try:
        report(3, "Validating the public web app URL…")
        fetch_result = _fetch_web_app(url)
    except (ValueError, httpx.HTTPError):
        logger.exception("Web app fetch validation failed")
        report(100, "Web app could not be fetched safely.")
        fetch = ScannerResult(
            "web_fetch",
            ScannerStatus.FAILED,
            errors=["The web app could not be fetched safely.", "WEB_FETCH_FAILED"],
        )
        return UploadScanResult(
            ScanVerdict.SCAN_FAILED,
            "The web app could not be fetched safely.",
            [fetch],
        )

    report(10, "Web page loaded; starting security analysis…")

    def scaled_progress(percent: int, message: str) -> None:
        report(10 + round(percent * 0.9), message)

    result = scan_upload(
        fetch_result.body, "index.html", progress_callback=scaled_progress
    )
    passive_findings = evaluate_passive_policy(fetch_result)
    result.scanner_results.insert(
        0,
        ScannerResult(
            "web_fetch",
            ScannerStatus.SUCCESS,
            metadata=fetch_result.metadata(),
        ),
    )
    dependency_result = next(
        (
            item for item in result.scanner_results
            if item.scanner == "dependencies"
            and item.metadata.get("not_applicable")
        ),
        None,
    )
    if dependency_result is not None:
        dependency_result.status = ScannerStatus.PARTIAL
        dependency_result.errors = [
            "Delivered client assets and bundle versions were not dependency-scanned."
        ]
        dependency_result.metadata = {
            **dependency_result.metadata,
            "not_applicable": False,
            "coverage": "ENTRY_HTML_ONLY",
            "version_inference": "NOT_PERFORMED",
        }
    result.scanner_results.insert(
        1,
        ScannerResult(
            "web_passive",
            ScannerStatus.PARTIAL if passive_findings else ScannerStatus.SUCCESS,
            findings=passive_findings,
            metadata={
                "response_url": redact_url(fetch_result.final_url),
                "cookies_inspected": len(fetch_result.cookies),
                "coverage_complete": not fetch_result.metadata_truncated,
                "address_pinned": fetch_result.address_pinned,
            },
        ),
    )
    if any(
        item["severity"] in {"HIGH", "CRITICAL"} and item["confidence"] >= 0.7
        for item in passive_findings
    ):
        result.verdict = ScanVerdict.BLOCKED
        result.reason = "The deployed web response contains a blocking security finding."
    elif (
        (passive_findings or dependency_result is not None)
        and result.verdict == ScanVerdict.PASSED
    ):
        result.verdict = ScanVerdict.REVIEW_REQUIRED
        result.reason = "The deployed web response or asset coverage requires security review."
    return result


def scan_upload(
    data: bytes | bytearray | memoryview,
    filename: str,
    progress_callback: ScanProgressCallback | None = None,
) -> UploadScanResult:
    """Run every required stage and never confuse missing analysis with a pass."""
    def report(percent: int, message: str) -> None:
        if progress_callback is not None:
            progress_callback(percent, message)

    report(2, "Preparing secure scan workspace…")
    scratch = ensure_scratch_directory()
    with tempfile.TemporaryDirectory(
        prefix="crucible_upload_", dir=scratch,
    ) as temp:
        root = Path(temp)
        try:
            report(8, "Validating and safely extracting the application…")
            files = _extract_upload(data, filename, root)
        except Exception:
            logger.exception("Archive validation failed")
            report(100, "Archive validation failed.")
            archive = ScannerResult(
                "archive_validation", ScannerStatus.FAILED,
                errors=["The uploaded archive could not be safely extracted.", "ARCHIVE_EXTRACTION_FAILED"],
            )
            return UploadScanResult(
                ScanVerdict.SCAN_FAILED,
                "The uploaded archive could not be safely extracted.",
                [archive],
            )
        app_root = root / "app"
        all_files = [path for path in app_root.rglob("*") if path.is_file()]
        report(20, "Validating source and configuration files…")
        syntax = safely_run_stage("syntax", lambda: _validate_syntax(files, app_root))
        if syntax.status == ScannerStatus.FAILED:
            report(100, "Source validation failed.")
            return UploadScanResult(
                ScanVerdict.BLOCKED, "App rejected: source validation failed.",
                [syntax], len(files),
            )
        results = [syntax]
        report(35, "Running static security rules…")
        results.append(
            safely_run_stage("semgrep", lambda: _run_semgrep(app_root, files))
        )
        report(55, "Running model-assisted security review…")
        results.append(
            safely_run_stage("claude", lambda: _run_claude(files, app_root))
        )
        report(72, "Checking application dependencies…")
        results.append(
            safely_run_stage(
                "dependencies", lambda: _run_dependencies(app_root, files)
            )
        )
        report(80, "Inspecting packaged desktop metadata and signatures…")
        artifact = safely_run_stage(
            "desktop_artifact", lambda: _run_desktop_artifact_inspection(app_root)
        )
        results.append(artifact)
        report(86, "Scanning files for malware…")
        results.append(
            safely_run_stage("malware", lambda: _run_malware(app_root, all_files))
        )
        report(96, "Calculating the final security verdict…")
        verdict = determine_verdict(results)
        if artifact.status == ScannerStatus.FAILED:
            verdict = ScanVerdict.SCAN_FAILED
        elif (
            artifact.status == ScannerStatus.PARTIAL
            and verdict == ScanVerdict.PASSED
        ):
            verdict = ScanVerdict.REVIEW_REQUIRED
        reasons = {
            ScanVerdict.PASSED: "All required scanners completed with no blocking findings.",
            ScanVerdict.BLOCKED: "The app contains a blocking security finding.",
            ScanVerdict.REVIEW_REQUIRED: "Analysis was partial or requires human evidence.",
            ScanVerdict.SCAN_FAILED: "Required security analysis did not complete.",
        }
        report(100, "Security scan complete.")
        return UploadScanResult(verdict, reasons[verdict], results, len(files))
