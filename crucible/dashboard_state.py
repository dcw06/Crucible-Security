"""Small, framework-independent helpers for Streamlit upload state."""

from __future__ import annotations

from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

SUPPORTED_UPLOAD_SUFFIXES = {
    ".zip", ".dmg", ".pkg", ".exe", ".msi", ".msix", ".appimage", ".deb",
    ".rpm", ".snap", ".py", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts",
    ".tsx", ".mts", ".cts", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
    ".hh", ".hxx", ".cs", ".json", ".yaml", ".yml", ".xml", ".toml",
    ".ini", ".cfg", ".conf", ".properties", ".gradle",
}
SUPPORTED_UPLOAD_NAMES = {
    "dockerfile", "makefile", "pom.xml", "package.json", "package-lock.json",
    "requirements.txt", "pyproject.toml",
}


def rotate_upload_widget(session_state: MutableMapping[str, Any]) -> int:
    """Invalidate the current uploader after every completed scan attempt."""
    generation = int(session_state.get("upload_widget_generation", 0)) + 1
    session_state["upload_widget_generation"] = generation
    return generation


def uipath_publication_state(run: MutableMapping[str, Any]) -> tuple[str, str]:
    """Return a concise status and pass-rate label for a pipeline run."""
    rate = run.get("tc_pass_rate")
    if isinstance(rate, (int, float)) and not isinstance(rate, bool):
        return "Confirmed", f"{float(rate):.0%}"
    step = int(run.get("step") or 0)
    label = str(run.get("step_label") or "")
    if step >= 9 or label.startswith("TC unavailable"):
        return "Unavailable", "—"
    if step >= 8 or "TC" in label:
        return "Publishing", "—"
    return "Pending", "—"


def lock_application_target(
    session_state: MutableMapping[str, Any], application_type: str,
) -> None:
    """Lock the target kind after a user supplies a desktop file or web URL."""
    if application_type not in {"Desktop app", "Web app"}:
        raise ValueError("Unsupported application target type")
    session_state["application_type"] = application_type
    session_state["application_target_locked"] = True
    session_state["scan_confirmed"] = False
    session_state.pop("last_scan_error", None)
    session_state.pop("last_upload_scan", None)
    session_state.pop("last_upload_application_type", None)
    session_state.pop("last_browser_evidence", None)


def cancel_application_target(
    session_state: MutableMapping[str, Any],
) -> None:
    """Clear the active target and permit switching application types again."""
    application_type = session_state.get("application_type")
    if application_type == "Desktop app":
        generation = int(session_state.get("upload_widget_generation", 0))
        session_state.pop(f"source_upload_{generation}", None)
        rotate_upload_widget(session_state)
    elif application_type == "Web app":
        session_state.pop("web_url", None)
        session_state.pop("web_requirements_text", None)
        session_state.pop("run_browser_tests", None)
        session_state.pop("target_authorized", None)
    session_state["application_target_locked"] = False
    session_state["scan_confirmed"] = False
    session_state.pop("last_scan_error", None)
    session_state.pop("last_upload_scan", None)
    session_state.pop("last_upload_application_type", None)
    session_state.pop("last_browser_evidence", None)


def upload_filename_supported(filename: str) -> bool:
    """Return whether the UI can route this upload to a meaningful scanner."""
    path = Path(filename)
    return (
        path.name.casefold() in SUPPORTED_UPLOAD_NAMES
        or path.suffix.casefold() in SUPPORTED_UPLOAD_SUFFIXES
    )


def finish_desktop_target(session_state: MutableMapping[str, Any]) -> None:
    """Schedule widget cleanup for the next rerun and unlock target selection."""
    generation = int(session_state.get("upload_widget_generation", 0))
    session_state["pending_upload_cleanup_key"] = f"source_upload_{generation}"
    session_state["pending_scan_confirmation_reset"] = True
    rotate_upload_widget(session_state)
    session_state["application_target_locked"] = False


def apply_pending_widget_resets(session_state: MutableMapping[str, Any]) -> None:
    """Apply post-scan resets before Streamlit instantiates their widgets."""
    upload_key = session_state.pop("pending_upload_cleanup_key", None)
    if isinstance(upload_key, str):
        session_state.pop(upload_key, None)
    if session_state.pop("pending_scan_confirmation_reset", False):
        session_state["scan_confirmed"] = False
