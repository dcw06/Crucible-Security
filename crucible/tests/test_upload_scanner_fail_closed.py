"""Regression tests for upload scanner execution status handling."""

import io
import plistlib
import stat
import zipfile
from types import SimpleNamespace

import httpx
import upload_scanner as scanner
from scan_models import ScannerStatus


def test_readiness_uses_local_semgrep_rules_and_no_osv_network(monkeypatch):
    commands = []
    monkeypatch.setattr(scanner, "_resolve_tool", lambda name: f"/tools/{name}")
    monkeypatch.setattr(scanner, "_tool_version", lambda binary: "1.0")

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", run)

    readiness = scanner.check_scanner_readiness()

    assert all(state["available"] for state in readiness.values())
    assert len(commands) == 2
    semgrep_command = next(command for command in commands if "semgrep" in command[0])
    assert semgrep_command[semgrep_command.index("--config") + 1].endswith(
        "readiness.yml"
    )
    assert all("osv-scanner" not in command[0] for command in commands)


def test_missing_claude_key_is_explicit_failure(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    source = tmp_path / "app.py"
    source.write_text("print('safe')", encoding="utf-8")
    result = scanner._run_claude([source], tmp_path)
    assert result.status == ScannerStatus.FAILED
    assert "API key" in result.errors[0]


def test_unknown_claude_category_is_preserved():
    finding = scanner.ClaudeFinding(
        title="Unsafe reflection",
        vulnerability_type="brand_new_weakness",
        severity="HIGH",
        confidence=0.9,
        evidence="User input reaches reflection API",
    )
    normalized = scanner._normalize_claude_finding(finding)
    assert normalized["vulnerability_type"] == "BRAND_NEW_WEAKNESS"
    assert normalized["mapped"] is False
    assert normalized["requires_mapping_review"] is True


def test_semgrep_nonzero_exit_is_failure(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("x = 1", encoding="utf-8")
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=2, stdout="{}", stderr="rules failed",
        ),
    )
    result = scanner._run_semgrep(tmp_path, [source])
    assert result.status == ScannerStatus.FAILED


def test_semgrep_errors_array_is_partial(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("x = 1", encoding="utf-8")
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"results": [], "errors": [{"message": "parse failed"}]}',
            stderr="",
        ),
    )
    result = scanner._run_semgrep(tmp_path, [source])
    assert result.status == ScannerStatus.PARTIAL


def test_missing_dependency_scanner_cannot_pass(monkeypatch, tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("example==1.0", encoding="utf-8")
    monkeypatch.setattr(scanner.shutil, "which", lambda _: None)
    result = scanner._run_dependencies(tmp_path, [manifest])
    assert result.status == ScannerStatus.FAILED


def test_missing_malware_engine_cannot_pass(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("x = 1", encoding="utf-8")
    monkeypatch.setattr(scanner.shutil, "which", lambda _: None)
    result = scanner._run_malware(tmp_path, [source])
    assert result.status == ScannerStatus.FAILED


def test_malformed_typescript_is_flagged_unvalidated(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text("const broken: = ;", encoding="utf-8")
    result = scanner._validate_syntax([source], tmp_path)
    assert result.status == ScannerStatus.PARTIAL
    assert "app.ts" in result.metadata["source_unvalidated"]


def test_requirements_file_is_not_source_unvalidated(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("example==1.0", encoding="utf-8")
    result = scanner._validate_syntax([manifest], tmp_path)
    assert result.status == ScannerStatus.SUCCESS
    assert "requirements.txt" in result.metadata["not_syntax_applicable"]


def test_oversized_file_is_split_and_coverage_is_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_CLAUDE_CHUNKS", 1)
    source = tmp_path / "auth.py"
    source.write_text(("safe_line = 1\n" * 10_000), encoding="utf-8")
    chunks, omitted, coverage = scanner._claude_chunks([source], tmp_path)
    assert len(chunks) == 1
    assert omitted == ["auth.py"]
    assert coverage[0].complete is False
    assert coverage[0].chunks_total > coverage[0].chunks_analyzed


def test_claude_declared_incomplete_is_partial():
    coverage = [
        scanner.FileCoverage(
            path="app.py", original_characters=10, included_characters=10,
            complete=True, chunks_total=1, chunks_analyzed=1,
        )
    ]
    assert scanner._determine_claude_status(True, [], coverage) == ScannerStatus.PARTIAL


def test_incomplete_file_coverage_is_partial():
    coverage = [
        scanner.FileCoverage(
            path="auth.py", original_characters=90_000, included_characters=60_000,
            complete=False, omission_reason="GLOBAL_CHUNK_LIMIT",
            chunks_total=2, chunks_analyzed=1,
        )
    ]
    assert scanner._determine_claude_status(False, ["auth.py"], coverage) == ScannerStatus.PARTIAL


def test_strict_claude_schema_rejects_extra_fields():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        scanner.ClaudeFinding(
            title="Issue", vulnerability_type="TEST", severity="HIGH",
            confidence=0.9, evidence="evidence", unexpected=True,
        )


def test_invalid_product_control_id_is_preserved_but_not_mapped():
    finding = scanner.ClaudeFinding(
        title="Issue", vulnerability_type="TEST", severity="HIGH",
        confidence=0.9, evidence="evidence", product_control_ids=["FAKE-999"],
    )
    normalized = scanner._normalize_claude_finding(finding)
    assert normalized["mapped"] is False
    assert normalized["invalid_product_control_ids"] == ["FAKE-999"]


def test_unexpected_stage_exception_becomes_failed_result():
    def explode():
        raise OSError("sensitive host path")

    result = scanner.safely_run_stage("semgrep", explode)
    assert result.status == ScannerStatus.FAILED
    assert "sensitive host path" not in " ".join(result.errors)


def test_individual_source_file_uses_200_mb_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_SOURCE_UPLOAD_BYTES", 8)
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_UPLOAD_BYTES", 4)

    files = scanner._extract_upload(b"x = 123\n", "app.py", tmp_path)

    assert [path.name for path in files] == ["app.py"]


def test_individual_source_file_over_200_mb_limit_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_SOURCE_UPLOAD_BYTES", 7)

    import pytest

    with pytest.raises(ValueError, match="source file exceeds"):
        scanner._extract_upload(b"x = 123\n", "app.py", tmp_path)


def test_zip_archive_keeps_separate_smaller_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_UPLOAD_BYTES", 4)

    import pytest

    with pytest.raises(ValueError, match="ZIP archive exceeds"):
        scanner._extract_upload(b"not-a-zip", "app.zip", tmp_path)


def test_scan_upload_reports_stage_progress(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "ensure_scratch_directory", lambda: tmp_path)
    monkeypatch.setattr(scanner, "_extract_upload", lambda *_: [source])
    monkeypatch.setattr(
        scanner, "_validate_syntax",
        lambda *_: scanner.ScannerResult("syntax", ScannerStatus.SUCCESS),
    )
    monkeypatch.setattr(
        scanner, "_run_semgrep",
        lambda *_: scanner.ScannerResult("semgrep", ScannerStatus.SUCCESS),
    )
    monkeypatch.setattr(
        scanner, "_run_claude",
        lambda *_: scanner.ScannerResult("claude", ScannerStatus.SUCCESS),
    )
    monkeypatch.setattr(
        scanner, "_run_dependencies",
        lambda *_: scanner.ScannerResult("dependencies", ScannerStatus.SUCCESS),
    )
    monkeypatch.setattr(
        scanner, "_run_malware",
        lambda *_: scanner.ScannerResult("malware", ScannerStatus.SUCCESS),
    )
    updates = []

    result = scanner.scan_upload(
        b"x = 1\n",
        "app.py",
        lambda percent, message: updates.append((percent, message)),
    )

    assert result.verdict.value == "PASSED"
    assert [percent for percent, _ in updates] == sorted(
        percent for percent, _ in updates
    )
    assert updates[-1] == (100, "Security scan complete.")


def test_static_web_project_files_are_scannable(tmp_path):
    destination = tmp_path / "single"
    destination.mkdir()

    files = scanner._extract_upload(
        b"<main>Hello</main>\n", "index.html", destination
    )

    assert [path.name for path in files] == ["index.html"]


def test_web_url_rejects_private_network_targets(monkeypatch):
    import pytest

    monkeypatch.setattr(
        scanner.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (scanner.socket.AF_INET, scanner.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ],
    )

    with pytest.raises(ValueError, match="public addresses"):
        scanner._validate_public_web_url("https://localhost")


def test_web_url_accepts_public_https_target(monkeypatch):
    monkeypatch.setattr(
        scanner.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                scanner.socket.AF_INET,
                scanner.socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ],
    )

    assert (
        scanner._validate_public_web_url("https://example.com/app")
        == "https://example.com/app"
    )


def test_web_url_scan_records_fetch_scope(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "_fetch_web_app",
        lambda _url: scanner.WebFetchResult(
            body=b"<main>Safe</main>",
            requested_url="https://example.com/",
            final_url="https://example.com/",
            status_code=200,
            headers={
                "content-security-policy": ("default-src 'self'; frame-ancestors 'none'",),
                "strict-transport-security": ("max-age=31536000",),
                "x-content-type-options": ("nosniff",),
                "referrer-policy": ("strict-origin-when-cross-origin",),
                "permissions-policy": ("camera=(), microphone=()",),
            },
            cookies=(),
            redirects=(),
            resolved_ip="93.184.216.34",
            tls=scanner.TlsEvidence("example.com", True),
            address_pinned=True,
        ),
    )
    scanned = scanner.UploadScanResult(
        scanner.ScanVerdict.PASSED,
        "complete",
        [],
        1,
    )
    monkeypatch.setattr(scanner, "scan_upload", lambda *_args, **_kwargs: scanned)

    result = scanner.scan_web_url("https://example.com")

    assert result.verdict == scanner.ScanVerdict.PASSED
    assert result.scanner_results[0].scanner == "web_fetch"
    assert result.scanner_results[0].metadata["scope"].startswith(
        "delivered entry-page HTML"
    )
    assert result.scanner_results[1].scanner == "web_passive"


def _zip_with_symlink(target: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("Demo.app/Contents/Resources/app.py", "print('safe')\n")
        link = zipfile.ZipInfo("Demo.app/Contents/Resources/current.py")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, target)
    return buffer.getvalue()


def test_internal_archive_symlink_is_validated_but_not_materialized(tmp_path):
    files = scanner._extract_upload(
        _zip_with_symlink("app.py"), "Demo.app.zip", tmp_path
    )

    assert [path.name for path in files] == ["app.py"]
    assert not (
        tmp_path / "app" / "Demo.app" / "Contents" / "Resources" / "current.py"
    ).exists()


def test_archive_symlink_cannot_escape_bundle(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="escapes"):
        scanner._extract_upload(
            _zip_with_symlink("../../../../../etc/passwd"),
            "Demo.app.zip",
            tmp_path,
        )


def test_archive_total_entry_limit_counts_directories(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_ENTRIES", 3)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("one/", b"")
        archive.writestr("two/", b"")
        archive.writestr("three/", b"")
        archive.writestr("app.py", b"x = 1")

    import pytest
    with pytest.raises(ValueError, match="total entries"):
        scanner._extract_upload(buffer.getvalue(), "app.zip", tmp_path)


def test_archive_rejects_deep_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_PATH_DEPTH", 3)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("one/two/three/app.py", b"x = 1")

    import pytest
    with pytest.raises(ValueError, match="deeply nested"):
        scanner._extract_upload(buffer.getvalue(), "app.zip", tmp_path)


def test_archive_rejects_overlong_names(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_NAME_BYTES", 16)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("this-name-is-too-long.py", b"x = 1")

    import pytest
    with pytest.raises(ValueError, match="overlong"):
        scanner._extract_upload(buffer.getvalue(), "app.zip", tmp_path)


def test_archive_rejects_oversized_member(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_MEMBER_BYTES", 4)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", b"x = 123")

    import pytest
    with pytest.raises(ValueError, match="oversized member"):
        scanner._extract_upload(buffer.getvalue(), "app.zip", tmp_path)


def test_archive_rejects_extreme_compression_ratio(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "MAX_ARCHIVE_COMPRESSION_RATIO", 2)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("app.py", b"x" * 10_000)

    import pytest
    with pytest.raises(ValueError, match="compression ratio"):
        scanner._extract_upload(buffer.getvalue(), "app.zip", tmp_path)


def test_archive_extraction_has_wall_clock_budget(monkeypatch, tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", b"x = 1")
    observed = iter([0.0, scanner.MAX_ARCHIVE_PROCESS_SECONDS + 1.0])
    monkeypatch.setattr(scanner.time, "monotonic", lambda: next(observed))

    import pytest
    with pytest.raises(ValueError, match="time limit"):
        scanner._extract_upload(buffer.getvalue(), "app.zip", tmp_path)


def test_embedded_runtime_archive_is_kept_opaque(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("Demo.app/Contents/Resources/app.py", "print('safe')\n")
        archive.writestr("Demo.app/Contents/Resources/base_library.zip", b"opaque")

    files = scanner._extract_upload(buffer.getvalue(), "Demo.app.zip", tmp_path)

    assert [path.name for path in files] == ["app.py"]
    assert (
        tmp_path / "app" / "Demo.app" / "Contents" / "Resources" / "base_library.zip"
    ).read_bytes() == b"opaque"


def test_macos_artifact_without_platform_tool_requires_review(monkeypatch, tmp_path):
    bundle = tmp_path / "Demo.app" / "Contents"
    bundle.mkdir(parents=True)
    monkeypatch.setattr(scanner, "_resolve_tool", lambda _name: None)

    result = scanner._run_macos_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.PARTIAL
    assert result.metadata["platform"] == "macOS"


def test_macos_artifact_ignores_finder_metadata_bundle(monkeypatch, tmp_path):
    real = tmp_path / "Demo.app" / "Contents"
    metadata = tmp_path / "__MACOSX" / "Demo.app" / "Contents"
    real.mkdir(parents=True)
    metadata.mkdir(parents=True)
    monkeypatch.setattr(scanner, "_resolve_tool", lambda _name: None)

    result = scanner._run_macos_artifact_inspection(tmp_path)

    assert result.metadata["bundles"] == ["Demo.app"]


def test_malware_stage_receives_every_extracted_regular_file(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "ensure_scratch_directory", lambda: tmp_path)

    def extract(_data, _filename, destination):
        app = destination / "app"
        app.mkdir()
        source = app / "main.py"
        source.write_text("print('safe')\n", encoding="utf-8")
        (app / "native.dylib").write_bytes(b"binary")
        return [source]

    successful = lambda name: scanner.ScannerResult(name, ScannerStatus.SUCCESS)
    monkeypatch.setattr(scanner, "_extract_upload", extract)
    monkeypatch.setattr(scanner, "_validate_syntax", lambda *_: successful("syntax"))
    monkeypatch.setattr(scanner, "_run_semgrep", lambda *_: successful("semgrep"))
    monkeypatch.setattr(scanner, "_run_claude", lambda *_: successful("claude"))
    monkeypatch.setattr(
        scanner, "_run_dependencies", lambda *_: successful("dependencies")
    )
    monkeypatch.setattr(
        scanner, "_run_macos_artifact_inspection",
        lambda *_: successful("desktop_artifact"),
    )
    observed = {}

    def malware(_root, files):
        observed["names"] = sorted(path.name for path in files)
        return successful("malware")

    monkeypatch.setattr(scanner, "_run_malware", malware)

    result = scanner.scan_upload(b"archive", "Demo.app.zip")

    assert result.verdict == scanner.ScanVerdict.PASSED
    assert observed["names"] == ["main.py", "native.dylib"]


def test_packaged_desktop_binary_is_accepted_for_artifact_scanning(tmp_path):
    files = scanner._extract_upload(b"opaque installer", "Demo.dmg", tmp_path)

    assert files == []
    artifact = scanner._run_desktop_artifact_inspection(tmp_path / "app")
    assert artifact.status == ScannerStatus.PARTIAL
    assert artifact.metadata["platforms"] == ["macOS"]
    assert artifact.metadata["artifacts"][0]["content_matches_claim"] is False


def test_artifact_content_signature_is_recorded(tmp_path):
    artifact_path = tmp_path / "Demo.exe"
    artifact_path.write_bytes(b"MZ" + b"\0" * 32)

    result = scanner._run_desktop_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.PARTIAL
    assert result.metadata["artifacts"] == [{
        "path": "Demo.exe",
        "claimed_type": ".exe",
        "identified_type": ".exe",
        "content_matches_claim": True,
        "platform": "Windows",
    }]


def test_complete_attested_worker_can_complete_artifact_stage(
    monkeypatch, tmp_path
):
    artifact_path = tmp_path / "Demo.exe"
    artifact_path.write_bytes(b"MZ" + b"\0" * 32)
    monkeypatch.setenv("DESKTOP_INSPECTION_MODE", "remote")
    monkeypatch.setattr(
        scanner,
        "inspect_native_artifact",
        lambda *_: scanner.ScannerResult(
            "desktop_artifact", ScannerStatus.SUCCESS,
            metadata={"verified_attestation": True, "job_id": "native-1"},
        ),
    )

    result = scanner._run_desktop_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert result.metadata["worker_results"][0]["job_id"] == "native-1"


def test_complete_native_worker_allows_binary_only_final_pass(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "ensure_scratch_directory", lambda: tmp_path)

    def extract(_data, _filename, destination):
        app = destination / "app"
        app.mkdir()
        (app / "Demo.exe").write_bytes(b"MZ" + b"\0" * 32)
        return []

    successful = lambda name: scanner.ScannerResult(name, ScannerStatus.SUCCESS)
    monkeypatch.setattr(scanner, "_extract_upload", extract)
    monkeypatch.setattr(scanner, "_validate_syntax", lambda *_: successful("syntax"))
    monkeypatch.setattr(scanner, "_run_semgrep", lambda *_: successful("semgrep"))
    monkeypatch.setattr(
        scanner, "_run_claude",
        lambda *_: scanner.ScannerResult(
            "claude", ScannerStatus.SKIPPED,
            metadata={"not_applicable": True},
        ),
    )
    monkeypatch.setattr(
        scanner, "_run_dependencies", lambda *_: successful("dependencies")
    )
    monkeypatch.setattr(
        scanner, "_run_desktop_artifact_inspection",
        lambda *_: scanner.ScannerResult(
            "desktop_artifact", ScannerStatus.SUCCESS,
            metadata={"verified_attestation": True},
        ),
    )
    monkeypatch.setattr(scanner, "_run_malware", lambda *_: successful("malware"))

    result = scanner.scan_upload(b"binary", "Demo.exe")

    assert result.verdict == scanner.ScanVerdict.PASSED


def test_extracted_app_is_enveloped_for_macos_worker(monkeypatch, tmp_path):
    bundle = tmp_path / "Demo.app"
    executable = bundle / "Contents" / "MacOS" / "Demo"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"binary")
    executable.chmod(0o755)
    monkeypatch.setenv("DESKTOP_INSPECTION_MODE", "remote")
    monkeypatch.setattr(
        scanner, "_run_macos_artifact_inspection",
        lambda *_: scanner.ScannerResult(
            "desktop_artifact", ScannerStatus.PARTIAL,
            metadata={"platform": "macOS", "bundles": [{"path": "Demo.app"}]},
        ),
    )
    observed = {}

    def inspect(path, platform):
        observed["name"] = path.name
        observed["platform"] = platform
        with zipfile.ZipFile(path) as archive:
            observed["members"] = archive.namelist()
        return scanner.ScannerResult(
            "desktop_artifact", ScannerStatus.SUCCESS,
            metadata={"verified_attestation": True},
        )

    monkeypatch.setattr(scanner, "inspect_native_artifact", inspect)

    result = scanner._run_desktop_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert observed["name"] == "Demo.app.zip"
    assert observed["platform"] == "macOS"
    assert "Demo.app/Contents/MacOS/Demo" in observed["members"]


def test_mixed_platform_artifacts_are_all_reported(monkeypatch, tmp_path):
    contents = tmp_path / "Demo.app" / "Contents"
    contents.mkdir(parents=True)
    (tmp_path / "Setup.exe").write_bytes(b"MZ" + b"\0" * 32)
    (tmp_path / "Package.deb").write_bytes(b"!<arch>\n" + b"\0" * 32)
    monkeypatch.setattr(scanner, "_resolve_tool", lambda _name: None)

    result = scanner._run_desktop_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.PARTIAL
    assert result.metadata["platforms"] == ["Linux", "Windows", "macOS"]
    assert {
        item["path"] for item in result.metadata["artifacts"]
    } == {"Package.deb", "Setup.exe"}
    assert "macos" in result.metadata


def test_entitlement_failure_is_partial(monkeypatch, tmp_path):
    contents = tmp_path / "Demo.app" / "Contents"
    executable = contents / "MacOS" / "Demo"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"binary")
    executable.chmod(0o755)
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "example.Demo",
        "CFBundleExecutable": "Demo",
        "CFBundleVersion": "1",
    }))
    monkeypatch.setattr(scanner, "_resolve_tool", lambda _name: "/usr/bin/codesign")
    calls = iter([
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=1, stdout=b"", stderr=b"not signed"),
    ])
    monkeypatch.setattr(scanner.subprocess, "run", lambda *_args, **_kwargs: next(calls))

    result = scanner._run_macos_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.PARTIAL
    assert result.metadata["bundles"][0]["entitlement_inspection"] == "unavailable"
    assert any("entitlement inspection unavailable" in error for error in result.errors)


def test_invalid_entitlement_plist_is_partial(monkeypatch, tmp_path):
    contents = tmp_path / "Demo.app" / "Contents"
    executable = contents / "MacOS" / "Demo"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"binary")
    executable.chmod(0o755)
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "example.Demo",
        "CFBundleExecutable": "Demo",
        "CFBundleVersion": "1",
    }))
    monkeypatch.setattr(scanner, "_resolve_tool", lambda _name: "/usr/bin/codesign")
    calls = iter([
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=0, stdout=b"not a plist", stderr=b""),
    ])
    monkeypatch.setattr(scanner.subprocess, "run", lambda *_args, **_kwargs: next(calls))

    result = scanner._run_macos_artifact_inspection(tmp_path)

    assert result.status == ScannerStatus.PARTIAL
    assert result.metadata["bundles"][0]["entitlement_inspection"] == "invalid"


def test_missing_bundle_executable_is_blocking_finding(monkeypatch, tmp_path):
    contents = tmp_path / "Demo.app" / "Contents"
    contents.mkdir(parents=True)
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "example.Demo",
        "CFBundleExecutable": "Missing",
        "CFBundleVersion": "1",
    }))
    monkeypatch.setattr(scanner, "_resolve_tool", lambda _name: "/usr/bin/codesign")
    calls = iter([
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=0, stdout=plistlib.dumps({}), stderr=b""),
    ])
    monkeypatch.setattr(scanner.subprocess, "run", lambda *_args, **_kwargs: next(calls))

    result = scanner._run_macos_artifact_inspection(tmp_path)

    assert any(
        finding["vulnerability_type"] == "INVALID_BUNDLE_EXECUTABLE"
        for finding in result.findings
    )


def test_binary_only_artifact_does_not_claim_model_review(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = scanner._run_claude([], tmp_path)

    assert result.status == ScannerStatus.SKIPPED
    assert result.metadata["not_applicable"] is True


def test_claude_timeout_retries_are_bounded_and_reported(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CLAUDE_REVIEW_MAX_RETRIES", "1")
    monkeypatch.setenv("CLAUDE_REVIEW_TIMEOUT_SECONDS", "30")
    monkeypatch.setattr(
        scanner,
        "_claude_chunks",
        lambda *_: ([("app.py\nprint('safe')", ["app.py"])], [], []),
    )
    monkeypatch.setattr(scanner.time, "sleep", lambda _seconds: None)
    calls = {"count": 0}

    class Messages:
        @staticmethod
        def create(**_kwargs):
            calls["count"] += 1
            raise scanner.anthropic.APITimeoutError(
                request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
            )

    class Client:
        messages = Messages()

    monkeypatch.setattr(scanner.anthropic, "Anthropic", lambda **_kwargs: Client())

    result = scanner._run_claude([source], tmp_path)

    assert result.status == ScannerStatus.FAILED
    assert calls["count"] == 2
    assert result.metadata["attempts"] == 2
    assert result.metadata["retry_exhausted"] is True


def test_claude_schema_failures_retry_with_safe_feedback(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CLAUDE_REVIEW_MAX_RETRIES", "1")
    monkeypatch.setenv("CLAUDE_REVIEW_MAX_OUTPUT_TOKENS", "16384")
    monkeypatch.setattr(
        scanner,
        "_claude_chunks",
        lambda *_: ([("app.py\nprint('safe')", ["app.py"])], [], []),
    )
    prompts = []

    class Messages:
        @staticmethod
        def create(**kwargs):
            prompts.append(kwargs["messages"][0]["content"])
            return type(
                "Response",
                (),
                {
                    "content": [
                        type("Block", (), {"type": "text", "text": "{}"})()
                    ],
                    "stop_reason": "end_turn",
                },
            )()

    class Client:
        messages = Messages()

    monkeypatch.setattr(scanner.anthropic, "Anthropic", lambda **_kwargs: Client())

    result = scanner._run_claude([source], tmp_path)

    assert result.status == ScannerStatus.FAILED
    assert len(prompts) == 2
    assert "CORRECTION REQUIRED" in prompts[1]
    assert result.metadata["attempts"] == 2
    assert result.metadata["max_output_tokens"] == 16384
    assert result.metadata["retry_exhausted"] is True
    assert result.errors[-1] == "CLAUDE_SCHEMA_VALIDATION_FAILED"


def test_claude_accepts_compact_control_assessments_without_claiming_pass(
    monkeypatch, tmp_path
):
    source = tmp_path / "app.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        scanner,
        "_claude_chunks",
        lambda *_: (
            [("app.py\nprint('safe')", ["app.py"])],
            [],
            [
                scanner.FileCoverage(
                    path="app.py",
                    original_characters=14,
                    included_characters=14,
                    complete=True,
                    chunks_total=1,
                )
            ],
        ),
    )
    payload = {
        "findings": [],
        "control_assessments": [],
        "analyzed_files": ["app.py"],
        "omitted_files": [],
        "analysis_complete": True,
    }

    class Messages:
        @staticmethod
        def create(**_kwargs):
            return type(
                "Response",
                (),
                {
                    "content": [
                        type(
                            "Block",
                            (),
                            {"type": "text", "text": scanner.json.dumps(payload)},
                        )()
                    ],
                    "stop_reason": "end_turn",
                },
            )()

    class Client:
        messages = Messages()

    monkeypatch.setattr(scanner.anthropic, "Anthropic", lambda **_kwargs: Client())

    result = scanner._run_claude([source], tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert result.metadata["controls_assessed"] == 0
    assert result.metadata["controls_catalog_total"] == len(scanner.PRODUCT_CONTROLS)
    assert result.metadata["unreported_controls_are_passed"] is False


def test_claude_finding_normalizes_numeric_cwe_ids():
    finding = scanner.ClaudeFinding.model_validate(
        {
            "title": "Reflected script injection",
            "vulnerability_type": "XSS",
            "severity": "HIGH",
            "confidence": 0.9,
            "evidence": "Unescaped request data reaches HTML.",
            "cwe_ids": [79, "CWE-116"],
        }
    )

    assert finding.cwe_ids == ["CWE-79", "CWE-116"]
