"""Crucible web app: upload security scanner and existing PR run monitor."""

from __future__ import annotations

import hashlib
import os
import secrets
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import streamlit as st
from dotenv import load_dotenv

_CRUCIBLE_DIR = Path(__file__).resolve().parent
# Support both documented `crucible/.env` launches and workspace-root `make web`.
load_dotenv(dotenv_path=_CRUCIBLE_DIR / ".env", override=False)
load_dotenv(dotenv_path=_CRUCIBLE_DIR.parent / ".env", override=False)
logger = logging.getLogger(__name__)

try:
    from .agents.security import categorize_findings
    from .adapters import WebAppAdapter
    from .application_adapters import ApplicationTarget, EvidenceStatus, TargetKind
    from .browser_sandbox import configured_allowed_hosts
    from .scan_models import ScanVerdict, ScannerResult, ScannerStatus
    from .scanner_preload import (
        load_preloaded_scanner_readiness,
        preload_scanner_readiness,
        scanner_snapshot_generated_at,
    )
    from .dashboard_state import (
        apply_pending_widget_resets,
        cancel_application_target,
        finish_desktop_target,
        lock_application_target,
        rotate_upload_widget,
        upload_filename_supported,
        uipath_publication_state,
    )
    from .scanner_access import (
        SCAN_ADMISSION, authenticate_scanner_token, scanner_auth_required,
        validate_scanner_access_config,
    )
    from .state import (
        get_run, init_db, list_runs, list_upload_scans, record_upload_scan,
    )
    from .upload_scanner import (
        MAX_ARCHIVE_UPLOAD_BYTES,
        MAX_SOURCE_UPLOAD_BYTES,
        MAX_WEB_FETCH_BYTES,
        check_scanner_readiness,
        scan_upload,
        scan_web_url,
    )
except ImportError:  # Streamlit executes this file as a script.
    from agents.security import categorize_findings
    from adapters import WebAppAdapter
    from application_adapters import ApplicationTarget, EvidenceStatus, TargetKind
    from browser_sandbox import configured_allowed_hosts
    from scan_models import ScanVerdict, ScannerResult, ScannerStatus
    from scanner_preload import (
        load_preloaded_scanner_readiness,
        preload_scanner_readiness,
        scanner_snapshot_generated_at,
    )
    from dashboard_state import (
        apply_pending_widget_resets,
        cancel_application_target,
        finish_desktop_target,
        lock_application_target,
        rotate_upload_widget,
        upload_filename_supported,
        uipath_publication_state,
    )
    from scanner_access import (
        SCAN_ADMISSION, authenticate_scanner_token, scanner_auth_required,
        validate_scanner_access_config,
    )
    from state import (
        get_run, init_db, list_runs, list_upload_scans, record_upload_scan,
    )
    from upload_scanner import (
        MAX_ARCHIVE_UPLOAD_BYTES,
        MAX_SOURCE_UPLOAD_BYTES,
        MAX_WEB_FETCH_BYTES,
        check_scanner_readiness,
        scan_upload,
        scan_web_url,
    )


st.set_page_config(page_title="Crucible", page_icon="🔥", layout="wide")


@st.cache_resource(show_spinner="Loading scanner engines…")
def _scanner_readiness():
    """Initialize scanner readiness once and reuse it across UI reruns."""
    return load_preloaded_scanner_readiness() or check_scanner_readiness()

@st.cache_resource
def _initialize_state() -> None:
    init_db()


def _lock_web_target() -> None:
    if str(st.session_state.get("web_url", "")).strip():
        lock_application_target(st.session_state, "Web app")


def _lock_desktop_target(widget_key: str) -> None:
    if st.session_state.get(widget_key) is not None:
        lock_application_target(st.session_state, "Desktop app")


st.markdown(
    """
    <style>
      .stApp {
        background: #080b10;
        color: #f4f7fc;
      }
      [data-testid="stHeader"] { background: transparent; }
      [data-testid="stToolbar"], [data-testid="stDecoration"],
      [data-testid="stStatusWidget"] { display:none; }
      [data-testid="stAppViewContainer"] h1,
      [data-testid="stAppViewContainer"] h2,
      [data-testid="stAppViewContainer"] h3,
      [data-testid="stAppViewContainer"] h4 {
        color: #f7f9fd;
      }
      [data-testid="stAppViewContainer"] p,
      [data-testid="stAppViewContainer"] label,
      [data-testid="stCaptionContainer"] {
        color: #c8d0de;
      }
      [data-testid="stCaptionContainer"] {
        opacity: 1;
      }
      button[data-baseweb="tab"] p {
        color: #b8c1d0;
        font-weight: 650;
      }
      button[data-baseweb="tab"][aria-selected="true"] p {
        color: #ff6b5f;
      }
      [data-testid="stExpander"] summary,
      [data-testid="stExpander"] summary p {
        color: #cbd3e0;
      }
      [data-testid="stAlert"] p {
        color: inherit;
        opacity: 1;
      }
      .hero {
        padding: 2.4rem 2.6rem;
        border: 1px solid rgba(255,255,255,.11);
        border-radius: 22px;
        background:
          radial-gradient(circle at 85% 15%, rgba(255,89,57,.20), transparent 28%),
          linear-gradient(135deg, #121722 0%, #0d1119 100%);
        margin-bottom: 1.5rem;
      }
      .eyebrow { color:#ff6b49; letter-spacing:.14em; font-size:.76rem; font-weight:700; }
      .hero h1 {
        color:#f8f9fc;
        font-size:3.2rem;
        margin:.35rem 0 .5rem;
        line-height:1.02;
      }
      .hero p {
        color:#cbd3df;
        max-width:700px;
        font-size:1.05rem;
      }
      .status-card {
        padding: 1.1rem 1.25rem; border-radius:14px;
        border:1px solid rgba(255,255,255,.10); background:#10151e;
      }
      .status-card p { color:#d7deea !important; }
      div[data-testid="stFileUploader"] {
        border:1px dashed rgba(255,107,73,.55); border-radius:18px; padding:1rem;
        background:rgba(255,107,73,.035);
      }
      div[data-testid="stFileUploader"] section {
        background:#f2f4f8;
      }
      div[data-testid="stFileUploader"] section,
      div[data-testid="stFileUploader"] section * {
        color:#303744;
      }
      .stButton button:disabled,
      .stButton button:disabled p {
        color:#8e98a8 !important;
        opacity:1;
      }
      :focus-visible {
        outline:3px solid #ff8a70 !important;
        outline-offset:3px !important;
      }
      .target-summary {
        padding: 1rem 1.1rem;
        border: 1px solid rgba(255,255,255,.12);
        border-radius: 14px;
        background: #10151e;
        margin: .6rem 0;
      }
      .target-summary strong { color:#f7f9fd; }
      .safety-list { margin:.2rem 0; padding-left:1.2rem; }
      .safety-list li { margin:.55rem 0; color:#d7deea; }
      @media (max-width: 700px) {
        .block-container { padding-left:1rem; padding-right:1rem; }
        .hero { padding:1.35rem 1.2rem; border-radius:16px; }
        .hero h1 { font-size:2rem; line-height:1.08; }
        .hero p { font-size:.95rem; }
        .eyebrow { font-size:.7rem; letter-spacing:.1em; }
        [data-testid="stMetric"] { min-width: 140px; }
      }
      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
          scroll-behavior:auto !important;
          transition-duration:0.01ms !important;
          animation-duration:0.01ms !important;
        }
      }
    </style>
    <div class="hero">
      <div class="eyebrow">MULTI-AGENT SECURITY INTELLIGENCE</div>
      <h1>Ship code that can survive scrutiny.</h1>
      <p>Inspect source and application packages without executing uploaded code.
      Authorized web targets can also be tested in separately isolated workers.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

_initialize_state()

try:
    validate_scanner_access_config()
except RuntimeError:
    st.error(
        "🛑 Upload scanning is unavailable because access control is not safely configured."
    )
    st.stop()

if scanner_auth_required() and not st.session_state.get("scanner_authenticated", False):
    st.subheader("Authorized access required")
    with st.form("scanner_login", clear_on_submit=True):
        access_token = st.text_input("Scanner access token", type="password")
        submitted = st.form_submit_button("Unlock scanner", type="primary")
    if submitted:
        if authenticate_scanner_token(access_token):
            st.session_state["scanner_authenticated"] = True
            st.session_state["scanner_client_id"] = hashlib.sha256(
                access_token.encode()
            ).hexdigest()
            st.rerun()
        else:
            st.error("Invalid access token.")
    st.stop()

if "scanner_client_id" not in st.session_state:
    st.session_state["scanner_client_id"] = secrets.token_urlsafe(24)
apply_pending_widget_resets(st.session_state)
if "upload_widget_generation" not in st.session_state:
    st.session_state["upload_widget_generation"] = 0
if "application_type" not in st.session_state:
    st.session_state["application_type"] = "Desktop app"
if "application_target_locked" not in st.session_state:
    st.session_state["application_target_locked"] = False
if "scan_confirmed" not in st.session_state:
    st.session_state["scan_confirmed"] = False

scan_tab, history_tab, monitor_tab = st.tabs([
    "New scan", "Scan history", "PR pipeline",
])

with scan_tab:
    scan_mode = os.environ.get("SECURITY_SCAN_MODE", "production").lower()
    readiness = _scanner_readiness()
    unavailable = [name for name, state in readiness.items() if not state["available"]]
    if unavailable:
        message = "Required scanner engines unavailable: " + ", ".join(unavailable)
        if scan_mode == "production":
            st.error(f"🛑 {message}. Upload scanning is disabled.")
        else:
            st.warning(
                f"Development mode: {message}. Scans may run for UI testing but "
                "cannot receive PASSED."
            )
    with st.expander(
        f"Scanner readiness · {len(readiness) - len(unavailable)}/{len(readiness)} ready"
    ):
        generated_at = scanner_snapshot_generated_at()
        if generated_at:
            try:
                rendered_at = datetime.fromisoformat(
                    generated_at.replace("Z", "+00:00")
                ).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            except ValueError:
                rendered_at = generated_at
            st.caption(f"Last checked: {rendered_at}")
        st.dataframe([
            {
                "Engine": name,
                "Ready": state["available"],
                "Version": state["version"] or "—",
                "Error": state["error"] or "—",
            }
            for name, state in readiness.items()
        ], width="stretch", hide_index=True)
        if st.button("Recheck scanner engines", key="refresh_scanners"):
            with st.spinner("Checking scanner engines…"):
                preload_scanner_readiness()
            _scanner_readiness.clear()
            st.rerun()
    left, right = st.columns([1.35, 0.65], gap="large")
    with left:
        st.subheader("Choose a scan target")
        application_type = st.radio(
            "Application type",
            ["Desktop app", "Web app"],
            horizontal=True,
            key="application_type",
            disabled=st.session_state["application_target_locked"],
            help=(
                "Desktop apps may be packaged application bundles. Web apps may "
                "include frontend, backend, configuration, and dependency files."
            ),
        )
        if st.session_state["application_target_locked"]:
            st.caption(
                f"{application_type} target selected. Cancel it before switching "
                "application types."
            )
            if st.button(
                f"Cancel {application_type.lower()} target",
                key="cancel_application_target",
                width="stretch",
            ):
                cancel_application_target(st.session_state)
                st.rerun()
        upload = None
        web_url = str(st.session_state.get("web_url", ""))
        web_requirements_text = str(
            st.session_state.get("web_requirements_text", "")
        )
        run_browser_tests = bool(st.session_state.get("run_browser_tests", False))
        target_authorized = bool(st.session_state.get("target_authorized", False))
        if application_type == "Web app":
            st.caption(
                "Enter an authorized public HTTPS URL. Passive checks do not execute "
                "page scripts in the scanner process."
            )
            web_url = st.text_input(
                "Web app URL",
                placeholder="https://app.example.com",
                key="web_url",
                on_change=_lock_web_target,
            ).strip()
            with st.expander("Isolated browser testing"):
                dynamic_enabled = (
                    os.environ.get("WEB_DYNAMIC_MODE", "disabled").lower() == "remote"
                )
                st.caption(
                    "Runs non-destructive Chromium, Firefox, and WebKit checks in "
                    "the separately operated Playwright worker."
                )
                run_browser_tests = st.checkbox(
                    "Run isolated browser tests",
                    key="run_browser_tests",
                    disabled=not dynamic_enabled,
                )
                if not dynamic_enabled:
                    st.info(
                        "Browser testing is disabled until the remote worker is configured."
                    )
                if run_browser_tests:
                    target_authorized = st.checkbox(
                        "I own this target or have explicit permission to test it, "
                        "and I authorize non-destructive browser requests.",
                        key="target_authorized",
                    )
                    web_requirements_text = st.text_area(
                        "Optional requirements or user journeys",
                        placeholder=(
                            "The landing page displays the product name\n"
                            "The sign-in page is reachable"
                        ),
                        help=(
                            "Enter one observable, non-destructive requirement per line. "
                            "Secrets and production credentials must not be entered here."
                        ),
                        key="web_requirements_text",
                    )
        else:
            st.caption(
                "Upload source, a ZIP application, or a supported native package. "
                "Maximum upload size: 200 MB."
            )
            if application_type == "Desktop app":
                with st.expander("Native-package coverage limitations"):
                    st.write(
                        "Package acceptance is not distribution approval. Signature, "
                        "provenance, installer, and binary checks require an isolated "
                        "platform worker. Missing evidence produces Needs review."
                    )
        if application_type == "Desktop app":
            upload_widget_key = (
                f"source_upload_{st.session_state['upload_widget_generation']}"
            )
            upload = st.file_uploader(
                "Application file",
                type=None,
                help=(
                    "Supported: source and configuration files, ZIP applications, "
                    "DMG, PKG, EXE, MSI, MSIX, AppImage, DEB, RPM, and Snap."
                ),
                key=upload_widget_key,
                on_change=_lock_desktop_target,
                args=(upload_widget_key,),
            )
        target_supported = True
        target_name = web_url
        target_detail = "Authorized deployed web target"
        if upload is not None:
            target_name = upload.name
            target_supported = upload_filename_supported(upload.name)
            target_detail = f"{upload.size / (1024 * 1024):.1f} MB"
            if not target_supported:
                st.error(
                    "This file type is not supported. Upload source code, a ZIP "
                    "application, or a documented native package."
                )
        if target_name:
            with st.container(border=True):
                st.markdown("**Selected target**")
                st.write(target_name)
                st.caption(target_detail)
            model_review = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
            with st.expander("Review scan plan", expanded=True):
                st.write(
                    "Planned engines: "
                    + ", ".join(
                        name for name, state in readiness.items()
                        if state["available"]
                    )
                )
                st.write(
                    "Model-assisted source review: "
                    + ("enabled" if model_review else "disabled")
                )
                if model_review and application_type == "Desktop app":
                    st.caption(
                        "Eligible source text may be sent to Anthropic. Uploaded "
                        "application binaries are not sent as model prompts."
                    )
                st.checkbox(
                    "I reviewed the target and scan plan",
                    key="scan_confirmed",
                )
        scan_target_available = (
            bool(web_url) if application_type == "Web app" else upload is not None
        )
        authorization_ready = not run_browser_tests or target_authorized
        scan_clicked = st.button(
            "Run security scan",
            type="primary",
            width="stretch",
            disabled=(
                not scan_target_available
                or not target_supported
                or not st.session_state["scan_confirmed"]
                or not authorization_ready
                or (scan_mode == "production" and bool(unavailable))
            ),
        )
        if scan_target_available:
            st.caption(
                "Keep this page open while the scan runs. Submitted scans cannot "
                "currently be interrupted safely."
            )

    with right:
        st.markdown("#### Safety gates")
        st.markdown(
            """
            <div class="status-card">
              <ul class="safety-list">
                <li>Bounded archive extraction</li>
                <li>Parser-based source validation</li>
                <li>Security, secrets, dependency, and malware checks</li>
                <li>Uploaded code is not executed in the upload scanner</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption(
            "Coverage depends on configured engines. Optional browser and test "
            "execution occurs only in separate isolated workers."
        )

    if st.session_state.get("last_scan_error"):
        st.error(st.session_state["last_scan_error"])
        if st.button("Dismiss error", key="dismiss_scan_error"):
            st.session_state.pop("last_scan_error", None)
            st.rerun()

    upload_limit = (
        MAX_ARCHIVE_UPLOAD_BYTES
        if upload and upload.name.lower().endswith(".zip")
        else MAX_SOURCE_UPLOAD_BYTES
    )
    if upload and upload.size > upload_limit:
        limit_mb = upload_limit // (1024 * 1024)
        upload_type = "ZIP archive" if upload.name.lower().endswith(".zip") else "source file"
        st.error(f"{upload_type} exceeds the {limit_mb} MB limit.")
    elif scan_target_available and scan_clicked:
        st.session_state.pop("last_scan_error", None)
        scan_reference = secrets.token_hex(8)
        admission_size = (
            MAX_WEB_FETCH_BYTES
            if application_type == "Web app"
            else upload.size
        )
        admission = SCAN_ADMISSION.acquire(
            st.session_state["scanner_client_id"], admission_size
        )
        if not admission.accepted:
            st.error(admission.reason)
        else:
            try:
                progress = st.progress(
                    0, text="Preparing your application for security analysis…"
                )

                def update_scan_progress(percent: int, message: str) -> None:
                    progress.progress(percent, text=message)

                if application_type == "Web app":
                    result = scan_web_url(
                        web_url,
                        progress_callback=(
                            lambda percent, message: update_scan_progress(
                                round(percent * 0.55), message
                            )
                            if run_browser_tests
                            else update_scan_progress(percent, message)
                        ),
                    )
                    st.session_state.pop("last_browser_evidence", None)
                    if run_browser_tests:
                        target_host = (
                            urlsplit(web_url).hostname or ""
                        ).lower().rstrip(".")
                        if target_host not in configured_allowed_hosts():
                            result.verdict = ScanVerdict.SCAN_FAILED
                            result.reason = (
                                "The web target is not present in WEB_ALLOWED_HOSTS."
                            )
                        else:
                            update_scan_progress(
                                60, "Submitting the authorized browser test plan…"
                            )
                            adapter = WebAppAdapter()
                            target = ApplicationTarget(
                                TargetKind.WEB,
                                web_url,
                                display_name=target_host,
                            )
                            requirements = [
                                {
                                    "req_id": f"USER-{index:03d}",
                                    "description": line.strip(),
                                }
                                for index, line in enumerate(
                                    web_requirements_text.splitlines(), start=1
                                )
                                if line.strip()
                            ][:16]
                            plan = adapter.generate_tests(target, requirements)
                            evidence = adapter.execute(target, plan)
                            st.session_state["last_browser_evidence"] = evidence
                            if not evidence.verified:
                                browser_result = ScannerResult(
                                    "browser_sandbox",
                                    ScannerStatus.FAILED,
                                    errors=list(evidence.infrastructure_errors),
                                )
                                result.verdict = ScanVerdict.SCAN_FAILED
                                result.reason = (
                                    "Required isolated browser testing did not complete."
                                )
                            else:
                                failed = [
                                    item for item in evidence.results
                                    if item.status == EvidenceStatus.FAILED
                                ]
                                review_required = [
                                    item for item in evidence.results
                                    if item.status == EvidenceStatus.SKIPPED
                                ]
                                browser_findings = [
                                    {
                                        "title": item.detail or item.test_id,
                                        "vulnerability_type": "BROWSER_TEST_FAILURE",
                                        "severity": item.severity,
                                        "confidence": item.confidence,
                                        "evidence": item.detail,
                                        "file_path": None,
                                        "line_number": None,
                                        "product_control_ids": [],
                                        "cwe_ids": [],
                                        "source": "browser_sandbox",
                                        "mapped": True,
                                        "status": "FINDING",
                                        "recommendation": (
                                            "Review the browser evidence and correct "
                                            "the failed user journey or security control."
                                        ),
                                    }
                                    for item in failed
                                ]
                                browser_findings.extend(
                                    {
                                        "title": item.detail or item.test_id,
                                        "vulnerability_type": "JOURNEY_MAPPING_REQUIRED",
                                        "severity": "INFO",
                                        "confidence": 1.0,
                                        "evidence": item.detail,
                                        "file_path": None,
                                        "line_number": None,
                                        "product_control_ids": [],
                                        "cwe_ids": [],
                                        "source": "browser_sandbox",
                                        "mapped": True,
                                        "status": "REVIEW_REQUIRED",
                                        "recommendation": (
                                            "Map this requirement to stable controls in "
                                            "the hashed application model."
                                        ),
                                    }
                                    for item in review_required
                                )
                                browser_findings.extend(
                                    {
                                        "title": str(
                                            item.get("type", "Passive browser finding")
                                        ),
                                        "vulnerability_type": str(
                                            item.get("type", "PASSIVE_WEB_SECURITY")
                                        ),
                                        "severity": str(item.get("severity", "INFO")),
                                        "confidence": float(
                                            item.get("confidence", 1.0)
                                        ),
                                        "evidence": str(item.get("evidence", "")),
                                        "file_path": None,
                                        "line_number": None,
                                        "product_control_ids": [],
                                        "cwe_ids": [],
                                        "source": "browser_sandbox",
                                        "mapped": True,
                                        "status": "FINDING",
                                        "recommendation": (
                                            "Apply the missing browser-facing security "
                                            "control and retest the deployed response."
                                        ),
                                    }
                                    for item in evidence.passive_findings
                                )
                                browser_result = ScannerResult(
                                    "browser_sandbox",
                                    (
                                        ScannerStatus.PARTIAL
                                        if browser_findings
                                        else ScannerStatus.SUCCESS
                                    ),
                                    findings=browser_findings,
                                    metadata={
                                        "sandbox_id": evidence.sandbox_id,
                                        "tests": len(evidence.results),
                                        "pass_rate": evidence.pass_rate,
                                        "accessibility_findings": len(
                                            evidence.accessibility_findings
                                        ),
                                        "passive_findings": len(
                                            evidence.passive_findings
                                        ),
                                    },
                                )
                                browser_blocking = any(
                                    item["severity"] in {"HIGH", "CRITICAL"}
                                    and item["confidence"] >= 0.7
                                    for item in browser_findings
                                )
                                if browser_blocking:
                                    result.verdict = ScanVerdict.BLOCKED
                                    result.reason = (
                                        "Isolated browser testing found a blocking "
                                        "security issue."
                                    )
                                elif (
                                    browser_findings
                                    and result.verdict == ScanVerdict.PASSED
                                ):
                                    result.verdict = ScanVerdict.REVIEW_REQUIRED
                                    result.reason = (
                                        "Isolated browser tests require human review."
                                    )
                            result.scanner_results.append(browser_result)
                            update_scan_progress(
                                100, "Static and browser analysis complete."
                            )
                else:
                    # getbuffer() avoids making a second full-size in-memory copy.
                    upload_buffer = upload.getbuffer()
                    result = scan_upload(
                        upload_buffer,
                        upload.name,
                        progress_callback=update_scan_progress,
                    )
                st.session_state["last_upload_scan"] = result
                st.session_state["last_upload_application_type"] = application_type
                findings = result.findings
                record_upload_scan(
                    scan_id=scan_reference,
                    target_type=application_type,
                    target_name=target_name,
                    verdict=result.verdict.value,
                    reason=result.reason,
                    files_scanned=result.files_scanned,
                    finding_count=len(findings),
                    critical_count=sum(
                        item.get("severity") == "CRITICAL" for item in findings
                    ),
                    high_count=sum(
                        item.get("severity") == "HIGH" for item in findings
                    ),
                )
            except Exception:
                logger.exception("Unexpected upload scan failure")
                st.session_state["last_scan_error"] = (
                    "The scan could not be completed. No upload was retained. "
                    "Review scanner readiness, then retry or choose another target. "
                    f"Reference: {scan_reference}"
                )
            finally:
                SCAN_ADMISSION.release()
                if "upload_buffer" in locals():
                    upload_buffer.release()
                    del upload_buffer
                # Rotate on success and failure so Streamlit releases the
                # UploadedFile associated with the completed attempt.
                if application_type == "Desktop app":
                    finish_desktop_target(st.session_state)
            st.rerun()

    result = st.session_state.get("last_upload_scan")
    if result:
        st.divider()
        result_application_type = st.session_state.get(
            "last_upload_application_type", "Application"
        )
        st.caption(f"Scan target: {result_application_type}")
        if result.verdict == ScanVerdict.PASSED:
            st.success(f"Passed — {result.reason}")
        elif result.verdict == ScanVerdict.REVIEW_REQUIRED:
            st.warning(f"Needs review — {result.reason}")
        elif result.verdict == ScanVerdict.SCAN_FAILED:
            st.error(f"Scan incomplete — {result.reason}")
        else:
            st.error(f"Blocked — {result.reason}")

        if result.scanner_results:
            st.subheader("Scanner coverage")
            coverage_rows = [
                {
                    "Scanner": scanner.scanner,
                    "Status": {
                        "SUCCESS": "Completed",
                        "FAILED": "Failed",
                        "PARTIAL": "Partial",
                        "SKIPPED": "Not applicable",
                    }.get(scanner.status.value, scanner.status.value),
                    "Findings": len(scanner.findings),
                    "Errors": " · ".join(error for error in scanner.errors if error),
                }
                for scanner in result.scanner_results
            ]
            st.dataframe(coverage_rows, width="stretch", hide_index=True)
            with st.expander("Scanner diagnostics and coverage details"):
                for scanner in result.scanner_results:
                    st.markdown(f"**{scanner.scanner} · {scanner.status.value}**")
                    if scanner.errors:
                        st.write("; ".join(scanner.errors))
                    if scanner.metadata:
                        st.json(scanner.metadata, expanded=False)

            browser_evidence = st.session_state.get("last_browser_evidence")
            if browser_evidence:
                st.subheader("Browser evidence")
                st.caption(
                    f"Attested sandbox job: {browser_evidence.sandbox_id or 'unverified'}"
                )
                st.dataframe(
                    [
                        {
                            "Test ID": item.test_id,
                            "Status": item.status.value,
                            "Severity": item.severity,
                            "Duration (ms)": item.duration_ms,
                            "Artifacts": len(item.artifacts),
                        }
                        for item in browser_evidence.results
                    ],
                    width="stretch",
                    hide_index=True,
                )
                with st.expander("Browser test details"):
                    for item in browser_evidence.results:
                        st.markdown(f"**{item.test_id} · {item.status.value}**")
                        st.write(item.detail or "No additional detail.")
                        st.caption(
                            f"Requirement: {item.requirement_id} · "
                            f"Console errors: {len(item.console_errors)} · "
                            f"Network failures: {len(item.network_failures)}"
                        )
                downloadable = [
                    (item.test_id, artifact)
                    for item in browser_evidence.results
                    for artifact in item.artifacts
                    if artifact.content is not None
                ]
                if downloadable:
                    with st.expander("Download browser evidence"):
                        for index, (test_id, artifact) in enumerate(downloadable):
                            st.download_button(
                                f"{test_id} · {artifact.name}",
                                data=artifact.content,
                                file_name=artifact.name,
                                mime=artifact.media_type,
                                key=f"browser_artifact_{index}_{artifact.sha256}",
                            )

            findings = result.findings
            omitted = [
                path
                for scanner in result.scanner_results
                for path in scanner.metadata.get("omitted_files", [])
            ]
            if omitted:
                st.warning(
                    "Model review omitted files; this scan cannot be treated as complete: "
                    + ", ".join(omitted[:20])
                )
            critical_count = sum(
                item.get("severity") == "CRITICAL" for item in findings
            )
            high_count = sum(item.get("severity") == "HIGH" for item in findings)
            a, b = st.columns(2)
            a.metric("Files scanned", result.files_scanned)
            b.metric("Critical", critical_count)
            c, d = st.columns(2)
            c.metric("High", high_count)
            d.metric("Total findings", len(findings))

            if findings:
                st.subheader("Security findings")
                severity_order = {
                    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                    "WARNING": 3, "INFO": 4,
                }
                for item in sorted(
                    findings,
                    key=lambda finding: severity_order.get(
                        str(finding.get("severity", "INFO")).upper(), 9,
                    ),
                ):
                    severity = str(item.get("severity", "INFO")).upper()
                    title = item.get("title", "Security finding")
                    with st.expander(f"{severity} · {title}"):
                        st.write(item.get("evidence") or "No evidence detail provided.")
                        location = item.get("file_path") or "Not file-specific"
                        if item.get("line_number"):
                            location += f":{item['line_number']}"
                        st.caption(
                            f"Source: {item.get('source', 'unknown')} · "
                            f"Location: {location}"
                        )
                        recommendation = item.get("recommendation")
                        if recommendation:
                            st.markdown(f"**Recommended action:** {recommendation}")
            else:
                st.info(
                    "No vulnerabilities were reported by scanners that completed. "
                    "Check scanner coverage above before interpreting this result."
                )

with history_tab:
    st.subheader("Recent upload scans")
    st.caption(
        "Only bounded summaries are retained. Uploaded files, source content, "
        "model evidence, and browser artifacts are not stored in scan history."
    )
    upload_history = list_upload_scans()
    if not upload_history:
        st.info("No completed upload scans have been recorded yet.")
    else:
        for item in upload_history:
            verdict_labels = {
                "PASSED": "Passed",
                "BLOCKED": "Blocked",
                "REVIEW_REQUIRED": "Needs review",
                "SCAN_FAILED": "Scan incomplete",
            }
            with st.expander(
                f"{verdict_labels.get(item['verdict'], item['verdict'])} · "
                f"{item['target_name']}"
            ):
                st.write(item["reason"])
                h1, h2 = st.columns(2)
                h1.metric("Files scanned", item["files_scanned"])
                h2.metric("Findings", item["finding_count"])
                h3, h4 = st.columns(2)
                h3.metric("Critical", item["critical_count"])
                h4.metric("High", item["high_count"])
                st.caption(
                    f"{item['target_type']} · {item['created_at']} · "
                    f"Reference {item['scan_id'][:12]}"
                )

with monitor_tab:
    st.subheader("Pull-request pipeline")
    st.caption(
        "Durable runs received through the configured GitHub webhook."
    )
    runs = list_runs()
    if not runs:
        st.info("No pull-request pipeline runs are available yet.")
    else:
        labels = [
            f"PR #{run['pr_number']} · {run.get('gate') or run.get('step_label', 'Queued')}"
            for run in runs
        ]
        index = st.selectbox("Pipeline run", range(len(runs)), format_func=labels.__getitem__)
        run = get_run(runs[index]["pr_number"])
        if run:
            gate = run.get("gate") or "IN PROGRESS"
            confidence = run.get("confidence")
            execution_rate = run.get("execution_pass_rate")
            tc_status, tc_rate_label = uipath_publication_state(run)
            findings = run.get("findings") or []
            cats = categorize_findings(findings)
            c1, c2, c3 = st.columns(3)
            c1.metric("Decision", gate)
            c2.metric("Confidence", "—" if confidence is None else f"{confidence:.0%}")
            c3.metric("Current step", run.get("step_label", "Queued"))
            c4, c5 = st.columns(2)
            c4.metric(
                "Sandbox pass rate",
                "—" if execution_rate is None else f"{execution_rate:.0%}",
            )
            c5.metric("UiPath Test Manager", tc_status)
            c6, c7 = st.columns(2)
            c6.metric("UiPath pass rate", tc_rate_label)
            c7.metric("Critical issues", len(cats["CRITICAL"]))
            st.caption(
                "UiPath Test Manager confirms publication of the sandbox results. "
                "The sandbox pass rate remains the authoritative merge-gate evidence."
            )
            tc_base = os.environ.get("TC_BASE_URL", "").strip()
            if tc_base.startswith("https://"):
                st.link_button("Open UiPath Test Manager", tc_base)
            st.caption(f"Analyzed commit: {(run.get('commit_sha') or '—')[:12]}")
            if confidence is not None:
                st.progress(confidence)
            if run.get("error_message"):
                st.error(run["error_message"])
            elif findings:
                st.subheader("Pipeline security findings")
                for item in findings:
                    severity = str(item.get("severity", "INFO")).upper()
                    with st.expander(
                        f"{severity} · {item.get('title', 'Security finding')}"
                    ):
                        st.write(item.get("evidence") or "No evidence detail provided.")
                        if item.get("recommendation"):
                            st.markdown(
                                f"**Recommended action:** {item['recommendation']}"
                            )
            else:
                st.success("No security findings recorded for this run.")

st.caption(
    "Crucible combines non-executing upload analysis with optional, authorized "
    "dynamic testing in separately isolated workers. Coverage depends on configured "
    "scanners and does not guarantee that an application is vulnerability-free."
)
