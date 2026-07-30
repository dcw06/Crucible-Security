"""Production configuration contracts for the large-upload profile."""

from pathlib import Path

import pytest
import yaml

import upload_limits
import upload_scanner
from dashboard_state import (
    apply_pending_widget_resets,
    cancel_application_target,
    finish_desktop_target,
    lock_application_target,
    rotate_upload_widget,
    upload_filename_supported,
    uipath_publication_state,
)
from scanner_access import ScanAdmissionController


ROOT = Path(__file__).parents[1]


def _dashboard_service() -> dict:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"]["dashboard"]


def test_deployed_streamlit_limit_accepts_largest_source_upload():
    environment = _dashboard_service()["environment"]
    streamlit_bytes = int(environment["STREAMLIT_SERVER_MAX_UPLOAD_SIZE"]) * upload_limits.MIB
    assert streamlit_bytes >= upload_limits.MAX_SOURCE_UPLOAD_BYTES


def test_deployed_profile_accepts_large_application_archives():
    environment = _dashboard_service()["environment"]
    assert int(environment["MAX_ARCHIVE_UPLOAD_BYTES"]) == 200 * upload_limits.MIB
    assert int(environment["MAX_EXTRACTED_BYTES"]) == 500 * upload_limits.MIB


def test_deployed_quota_accepts_largest_source_upload():
    environment = _dashboard_service()["environment"]
    assert int(environment["SCANNER_BYTE_QUOTA_BYTES"]) >= upload_limits.MAX_UPLOAD_BYTES
    assert int(environment["SCANNER_MAX_CONCURRENT"]) == 1


def test_scratch_and_database_use_separate_mounts():
    dashboard = _dashboard_service()
    assert any(
        item.startswith("/var/lib/crucible-scratch:")
        for item in dashboard["tmpfs"]
    )
    assert "crucible_state:/var/lib/crucible" in dashboard["volumes"]
    assert dashboard["environment"]["SCANNER_SCRATCH_DIR"] == "/var/lib/crucible-scratch"
    assert dashboard["environment"]["STATE_DB"].startswith("/var/lib/crucible/")


def test_clamav_signatures_are_updated_separately_and_read_only_to_dashboard():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert "clamav-updater" in compose["services"]
    assert "clamav_signatures:/var/lib/clamav:ro" in _dashboard_service()["volumes"]
    assert "clamav_signatures:/var/lib/clamav" in compose["services"]["clamav-updater"]["volumes"]


def test_uipath_publication_state_reports_confirmed_rate():
    assert uipath_publication_state({"tc_pass_rate": 2 / 3, "step": 10}) == (
        "Confirmed", "67%",
    )


def test_uipath_publication_state_distinguishes_pending_and_unavailable():
    assert uipath_publication_state({"step": 7}) == ("Pending", "—")
    assert uipath_publication_state({
        "step": 9,
        "step_label": "TC unavailable — sandbox result retained",
    }) == ("Unavailable", "—")


def test_desktop_target_locks_type_until_cancelled():
    state = {
        "upload_widget_generation": 2,
        "source_upload_2": object(),
    }
    lock_application_target(state, "Desktop app")
    assert state["application_target_locked"] is True
    assert state["application_type"] == "Desktop app"

    cancel_application_target(state)
    assert state["application_target_locked"] is False
    assert state["upload_widget_generation"] == 3
    assert "source_upload_2" not in state


def test_web_target_cancel_clears_target_specific_state():
    state = {
        "application_type": "Web app",
        "application_target_locked": True,
        "web_url": "https://example.test",
        "web_requirements_text": "Sign in",
        "run_browser_tests": True,
        "target_authorized": True,
    }
    cancel_application_target(state)
    assert state["application_target_locked"] is False
    assert "web_url" not in state
    assert "web_requirements_text" not in state
    assert "run_browser_tests" not in state
    assert "target_authorized" not in state


def test_cancel_clears_stale_result_and_error():
    state = {
        "application_type": "Web app",
        "last_upload_scan": object(),
        "last_scan_error": "failed",
    }
    cancel_application_target(state)
    assert "last_upload_scan" not in state
    assert "last_scan_error" not in state


def test_supported_upload_names_are_explicit():
    assert upload_filename_supported("application.zip")
    assert upload_filename_supported("service.py")
    assert upload_filename_supported("Dockerfile")
    assert not upload_filename_supported("video.mov")
    assert not upload_filename_supported("README")


def test_completed_desktop_target_unlocks_and_rotates_upload():
    state = {
        "application_target_locked": True,
        "scan_confirmed": True,
        "upload_widget_generation": 4,
        "source_upload_4": object(),
    }
    finish_desktop_target(state)
    assert state["application_target_locked"] is False
    assert state["scan_confirmed"] is True
    assert state["upload_widget_generation"] == 5
    assert state["pending_upload_cleanup_key"] == "source_upload_4"

    apply_pending_widget_resets(state)
    assert state["scan_confirmed"] is False
    assert "source_upload_4" not in state
    assert "pending_upload_cleanup_key" not in state


def test_runtime_config_rejects_quota_below_largest_upload(monkeypatch):
    monkeypatch.setenv(
        "SCANNER_BYTE_QUOTA_BYTES",
        str(upload_limits.MAX_UPLOAD_BYTES - 1),
    )
    monkeypatch.setenv("SCANNER_MAX_CONCURRENT", "1")
    with pytest.raises(RuntimeError, match="at least the largest upload"):
        upload_limits.validate_upload_runtime_config()


def test_runtime_config_rejects_concurrent_200_mb_scans(monkeypatch):
    monkeypatch.setenv(
        "SCANNER_BYTE_QUOTA_BYTES",
        str(upload_limits.MAX_UPLOAD_BYTES * 2),
    )
    monkeypatch.setenv("SCANNER_MAX_CONCURRENT", "2")
    with pytest.raises(RuntimeError, match="MAX_CONCURRENT=1"):
        upload_limits.validate_upload_runtime_config()


def test_default_admission_accepts_one_maximum_upload(monkeypatch):
    monkeypatch.delenv("SCANNER_BYTE_QUOTA_BYTES", raising=False)
    monkeypatch.delenv("SCANNER_MAX_CONCURRENT", raising=False)
    controller = ScanAdmissionController()
    admission = controller.acquire("large-upload", upload_limits.MAX_UPLOAD_BYTES)
    assert admission.accepted is True
    controller.release()


def test_widget_rotates_after_each_attempt():
    state = {"upload_widget_generation": 4}
    assert rotate_upload_widget(state) == 5
    assert state["upload_widget_generation"] == 5


def test_scan_scratch_is_removed_after_validation_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(upload_scanner, "ensure_scratch_directory", lambda: tmp_path)
    result = upload_scanner.scan_upload(b"not a zip", "broken.zip")
    assert result.accepted is False
    assert list(tmp_path.iterdir()) == []


def test_large_file_skips_memory_intensive_syntax_and_model_stages(
    monkeypatch, tmp_path,
):
    source = tmp_path / "large.py"
    source.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(upload_scanner, "MAX_SYNTAX_FILE_BYTES", 1)
    monkeypatch.setattr(upload_scanner, "MAX_CLAUDE_FILE_BYTES", 1)

    syntax = upload_scanner._validate_syntax([source], tmp_path)
    chunks, omitted, coverage = upload_scanner._claude_chunks([source], tmp_path)

    assert syntax.status.value == "PARTIAL"
    assert syntax.metadata["source_unvalidated"] == ["large.py"]
    assert chunks == []
    assert omitted == ["large.py"]
    assert coverage[0].omission_reason == "FILE_SIZE_LIMIT"
