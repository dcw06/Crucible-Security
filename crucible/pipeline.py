"""
pipeline.py — Crucible Pipeline Orchestrator
=============================================
Runs the full multi-agent pipeline for a single PR:

  Step 1: Fetch PR files (already done by webhook handler)
  Step 2: Requirements analysis
  Step 3-5: Writer/Critic adversarial loop (+ sequential Security scan per iteration)
  Step 6: optional remote-sandbox pytest execution → JUnit XML
  Step 7: TC upload + trigger + poll
  Step 8: Confidence score + PR comment
  Step 9: Maestro case (if CRITICAL)

Called by the background worker in main.py — never blocks the event loop.
"""

import asyncio
import ast
import os
import re
import tempfile
import traceback
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env", override=False)

try:
    from .agents import (
        analyze_requirements, write_tests, critique_tests, run_security_agent_files,
        MAX_ITERATIONS,
    )
    from .agents.security import has_critical, categorize_findings
    from .confidence import compute_confidence, format_pr_comment
    from .tc_client import full_tc_roundtrip, get_failing_tests
    from .state import update_step, upsert_run
    from .test_sandbox import (
        execute_generated_tests, fetch_source_snapshot, snapshot_source_files,
    )
except ImportError:  # Support direct execution from crucible/.
    from agents import (
        analyze_requirements, write_tests, critique_tests, run_security_agent_files,
        MAX_ITERATIONS,
    )
    from agents.security import has_critical, categorize_findings
    from confidence import compute_confidence, format_pr_comment
    from tc_client import full_tc_roundtrip, get_failing_tests
    from state import update_step, upsert_run
    from test_sandbox import (
        execute_generated_tests, fetch_source_snapshot, snapshot_source_files,
    )

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "")
MAESTRO_BASE = os.environ.get("MAESTRO_BASE_URL", "").rstrip("/")
MAESTRO_TOKEN = os.environ.get("MAESTRO_TOKEN", "")

FRAGILE_PATTERNS = [
    r"time\.sleep\(",
    r"datetime\.now\(",
    r"random\.",
    r"localhost:\d{4,5}",
    r"global\s+\w+",
    r"os\.environ\[",
]


def _detect_fragile(test_code: str) -> int:
    """Count how many FRAGILE pattern matches exist in the test file."""
    return sum(
        len(re.findall(p, test_code))
        for p in FRAGILE_PATTERNS
    )


def _requirement_marker_counts(test_code: str) -> dict[str, int]:
    """Count literal @pytest.mark.req_id markers in generated test functions."""
    counts: dict[str, int] = {}
    try:
        tree = ast.parse(test_code)
    except SyntaxError:
        return counts
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or len(decorator.args) != 1:
                continue
            func = decorator.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "req_id"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "mark"
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "pytest"
            ):
                continue
            value = decorator.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                counts[value.value] = counts.get(value.value, 0) + 1
    return counts


def _extract_docstrings(files: list[dict]) -> str:
    """Pull docstrings/comments from changed files for requirements analysis."""
    chunks = []
    for f in files:
        patch = f.get("patch", "")
        # grab added lines that look like docstrings or comments
        doc_lines = [
            line[1:] for line in patch.splitlines()
            if line.startswith("+") and ('"""' in line or "'''" in line or line.strip().startswith("#"))
        ]
        if doc_lines:
            chunks.append(f"# {f.get('filename', 'unknown')}\n" + "\n".join(doc_lines))
    return "\n\n".join(chunks)


def _build_diff(files: list[dict]) -> str:
    """Concatenate all file patches into a single diff string."""
    parts = []
    for f in files:
        filename = f.get("filename", "unknown")
        patch    = f.get("patch", "")
        if patch:
            parts.append(f"--- a/{filename}\n+++ b/{filename}\n{patch}")
    return "\n\n".join(parts)


async def _post_github_comment(pr_number: int, body: str) -> None:
    """Create or update Crucible's single report comment on the PR."""
    missing = [v for v, val in [
        ("GITHUB_TOKEN", GITHUB_TOKEN),
        ("GITHUB_OWNER", GITHUB_OWNER),
        ("GITHUB_REPO",  GITHUB_REPO),
    ] if not val]
    if missing:
        print(f"[Pipeline] {', '.join(missing)} not set — skipping PR comment")
        return
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/issues/{pr_number}/comments"
    async with httpx.AsyncClient() as client:
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
        }
        listing = await client.get(url, headers=headers, params={"per_page": 100}, timeout=15)
        existing_id = None
        if listing.status_code == 200:
            payload = listing.json()
            if isinstance(payload, list):
                for comment in payload:
                    if (
                        isinstance(comment, dict)
                        and "<!-- crucible-report -->" in str(comment.get("body", ""))
                        and isinstance(comment.get("id"), int)
                    ):
                        existing_id = comment["id"]
                        break
        if existing_id is not None:
            resp = await client.patch(
                f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
                f"/issues/comments/{existing_id}",
                headers=headers, json={"body": body}, timeout=15,
            )
        else:
            resp = await client.post(
                url, headers=headers, json={"body": body}, timeout=15,
            )
    if resp.status_code not in (200, 201):
        print(f"[Pipeline] PR comment failed: HTTP {resp.status_code}")
    else:
        print(f"[Pipeline] PR comment posted to #{pr_number}")


async def post_pipeline_failure(pr_number: int, commit_sha: str) -> None:
    """Publish a stable, credential-free terminal failure status."""
    if not await _pr_head_matches(pr_number, commit_sha):
        print(
            f"[Pipeline] Failure status for PR #{pr_number} was not published "
            "because the head commit changed"
        )
        return
    await _post_github_comment(
        pr_number,
        (
            "<!-- crucible-report -->\n"
            "## Crucible analysis failed\n\n"
            "The analysis could not be completed after bounded automatic retries. "
            "A maintainer should inspect the structured service logs and retry the workflow.\n\n"
            f"Analyzed commit: `{commit_sha}`"
        ),
    )


async def _pr_head_matches(pr_number: int, expected_sha: str) -> bool:
    """Fail closed if the PR advanced while this analysis was running."""
    if not all((GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO)):
        return False
    url = (
        f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
        f"/pulls/{pr_number}"
    )
    async with httpx.AsyncClient() as client:
        response = await client.get(
            url,
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
            },
            timeout=15,
        )
    if response.status_code != 200:
        return False
    payload = response.json()
    if not isinstance(payload, dict):
        return False
    head = payload.get("head")
    return isinstance(head, dict) and head.get("sha") == expected_sha


async def _open_maestro_case(findings: list[dict], pr_number: int) -> str | None:
    """Open a Maestro case for CRITICAL security findings. Returns case ID or None."""
    if not MAESTRO_BASE or not MAESTRO_TOKEN:
        print("[Pipeline] Maestro not configured — logging CRITICAL finding locally")
        return None

    # Use has_critical() — it applies _severity() which maps semgrep ERROR → CRITICAL.
    # Checking raw semgrep severity for "CRITICAL" would always miss (semgrep uses "ERROR").
    if not has_critical(findings):
        return None

    # Find the first CRITICAL-equivalent finding for the case description
    # categorize_findings() applies _severity() mapping (semgrep ERROR → CRITICAL)
    cats = categorize_findings(findings)
    critical = cats["CRITICAL"]
    sample = critical[0]
    rule_id = sample.get("check_id") or sample.get("rule_id", "unknown")
    line    = sample.get("start", {}).get("line", "?")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{MAESTRO_BASE}/api/v1/Maestro/Cases",
            headers={"Authorization": f"Bearer {MAESTRO_TOKEN}",
                     "Content-Type": "application/json"},
            json={
                "title": f"CRITICAL security finding in PR #{pr_number}",
                "severity": "HIGH",
                "description": (
                    f"Crucible detected a CRITICAL Semgrep finding.\n\n"
                    f"Rule: {rule_id}\nLine: {line}\n"
                    f"PR: #{pr_number}"
                ),
            },
            timeout=15,
        )

    if resp.status_code in (200, 201):
        data    = resp.json()
        case_id = data.get("id") or data.get("caseId", "CASE-UNKNOWN")
        print(f"[Pipeline] Maestro case opened: {case_id}")
        return str(case_id)
    else:
        print(f"[Pipeline] Maestro case failed: HTTP {resp.status_code} {resp.text[:200]}")
        return None


async def run_pipeline(files: list[dict], pr_number: int, commit_sha: str) -> None:
    """
    Full Crucible pipeline for one PR. Called by the asyncio.Queue worker.
    Updates SQLite state at each step for the Streamlit dashboard.
    """
    print(f"\n{'='*60}")
    print(f"[Pipeline] Starting PR #{pr_number}")
    print(f"{'='*60}")

    upsert_run(
        pr_number, expected_commit_sha=commit_sha,
        step=1, step_label="Webhook received & verified",
        error_message=None,
    )

    try:
        snapshot = await fetch_source_snapshot(commit_sha)
        if snapshot is None:
            raise RuntimeError("Immutable PR source snapshot could not be fetched")
        expected_source_files = [
            file.get("filename", "") for file in files
            if file.get("status") != "removed" and file.get("filename")
        ]
        source_files, missing_source_files = snapshot_source_files(
            snapshot, expected_source_files,
        )
        if missing_source_files:
            raise RuntimeError(
                f"PR source coverage incomplete for {len(missing_source_files)} changed file(s)"
            )

        # ── Step 2: Get failing tests from TC (inbound) ───────────────────
        update_step(pr_number, 2, "Fetching current TC failures", commit_sha)
        async with httpx.AsyncClient() as client:
            failing_tests = await get_failing_tests(client)
        if failing_tests:
            print(f"[Pipeline] {len(failing_tests)} currently failing TC tests noted for Writer")

        # ── Step 3: Requirements analysis ─────────────────────────────────
        update_step(pr_number, 3, "Requirements analyzed", commit_sha)
        pr_description = f"PR #{pr_number} changes: " + ", ".join(
            f.get("filename", "") for f in files
        )
        docstrings = _extract_docstrings(files)
        requirements = await asyncio.to_thread(
            analyze_requirements,
            pr_description,
            docstrings,
        )
        req_ids = [r["req_id"] for r in requirements]
        print(f"[Pipeline] Requirements: {req_ids}")

        # ── Steps 4–6: Writer / Critic adversarial loop ───────────────────
        diff = _build_diff(files)
        current_code: str | None = None
        feedback:     str | None = None
        approved      = False
        iteration     = 0

        # Security scan state
        findings:         list[dict] = []
        security_summary: str        = "No security issues found."

        for iteration in range(1, MAX_ITERATIONS + 1):
            # Writer
            update_step(
                pr_number, 4,
                f"Tests generated (Writer — iteration {iteration})",
                commit_sha,
            )
            # Pass failing_tests on iteration 1 only — gives Writer TC context;
            # subsequent iterations are guided by the Critic's feedback instead.
            current_code = await asyncio.to_thread(
                write_tests,
                diff, requirements, current_code, feedback, iteration,
                failing_tests if iteration == 1 else None,
            )

            # Critic
            update_step(
                pr_number, 5,
                f"Tests reviewed (Critic — iteration {iteration})",
                commit_sha,
            )
            approved, feedback = await asyncio.to_thread(
                critique_tests, current_code, iteration,
            )

            # Scan complete changed files from the immutable commit snapshot,
            # preserving paths/languages, plus the generated test file.
            update_step(pr_number, 6, "Security scanned (Semgrep)", commit_sha)
            scan_files = dict(source_files)
            scan_files["crucible_generated_tests.py"] = current_code
            findings, _, security_summary = await run_security_agent_files(scan_files)

            if approved:
                break

        fragile_count = _detect_fragile(current_code or "")
        marker_counts = _requirement_marker_counts(current_code or "")
        if fragile_count > 0:
            print(f"[Pipeline] ⚡ {fragile_count} FRAGILE pattern(s) detected")

        # ── Step 7: Execute only through an independently isolated service ─
        update_step(
            pr_number, 7, "Submitting tests to isolated sandbox", commit_sha,
        )
        xml_path: str | None = None
        execution = await execute_generated_tests(
            current_code or "", snapshot=snapshot, expected_requirement_ids=req_ids,
        )
        if execution.status == "SUCCESS" and execution.junit_xml:
            xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="crucible_results_")
            os.close(xml_fd)
            Path(xml_path).write_bytes(execution.junit_xml)
            update_step(
                pr_number, 7, "Tests executed in isolated sandbox", commit_sha,
            )
        else:
            update_step(
                pr_number, 7,
                f"Test execution {execution.status.lower()}",
                commit_sha,
            )
            print(f"[Pipeline] {execution.detail}")

        if not await _pr_head_matches(pr_number, commit_sha):
            upsert_run(
                pr_number, expected_commit_sha=commit_sha,
                step=-1, step_label="Superseded or unverifiable",
                error_message="Analysis was not published because the PR head changed.",
            )
            return

        # ── Steps 8–9: TC upload + poll ────────────────────────────────────
        update_step(
            pr_number, 8,
            "Uploading sandbox results to TC" if xml_path else "TC upload skipped — no sandbox result",
            commit_sha,
        )
        tc_pass_rate: float | None = None
        try:
            if xml_path and Path(xml_path).exists():
                tc_pass_rate = await full_tc_roundtrip(
                    xml_path, pr_number=pr_number, commit_sha=commit_sha,
                )
        finally:
            # Always clean up the XML tempfile — even if full_tc_roundtrip raises
            if xml_path:
                Path(xml_path).unlink(missing_ok=True)

        update_step(
            pr_number, 9,
            "TC run polled & confirmed" if tc_pass_rate is not None else "TC unavailable — sandbox result retained",
            commit_sha,
        )

        # ── Confidence score ──────────────────────────────────────────────
        cats        = categorize_findings(findings)
        is_critical = has_critical(findings)
        req_coverage = {
            req_id: int(execution.requirement_results.get(req_id, {}).get("collected", 0))
            for req_id in req_ids
        }
        coverage_verified = (
            execution.verified
            and all(marker_counts.get(req_id, 0) > 0 for req_id in req_ids)
            and all(req_coverage.get(req_id, 0) > 0 for req_id in req_ids)
        )
        result      = compute_confidence(
            iteration      = iteration,
            warnings       = len(cats["WARNING"]),
            errors         = len(cats["ERROR"]),
            any_critical   = is_critical,
            tc_pass_rate   = tc_pass_rate,
            fragile_count  = fragile_count,
            req_coverage   = req_coverage,
            critic_approved = approved,
            sandbox_verified = execution.verified,
            sandbox_tests_passed = execution.tests_passed,
            coverage_verified = coverage_verified,
            execution_pass_rate = execution.pass_rate,
            commit_sha        = commit_sha,
        )

        print(f"[Pipeline] Confidence={result.confidence:.2f} Gate={result.gate}")

        # Persist final state to SQLite
        upsert_run(
            pr_number,
            expected_commit_sha = commit_sha,
            step             = 10,
            step_label       = "Complete",
            confidence       = result.confidence,
            tc_pass_rate     = tc_pass_rate,
            execution_pass_rate = execution.pass_rate,
            findings         = findings,
            req_coverage     = result.req_coverage,
            fragile_count    = fragile_count,
            security_summary = security_summary,
            gate             = result.gate,
            error_message    = None,
        )

        # ── Maestro (CRITICAL only) ────────────────────────────────────────
        maestro_case_id: str | None = None
        if is_critical:
            maestro_case_id = await _open_maestro_case(findings, pr_number)

        # ── PR comment ────────────────────────────────────────────────────
        comment = format_pr_comment(
            result,
            pr_number       = pr_number,
            security_summary = security_summary,
            maestro_case_id = maestro_case_id,
            commit_sha       = commit_sha,
        )
        await _post_github_comment(pr_number, comment)

        print(f"[Pipeline] PR #{pr_number} complete — {result.gate_emoji} {result.gate}")

    except Exception as e:
        print(f"[Pipeline] ERROR on PR #{pr_number}: {e}")
        traceback.print_exc()
        upsert_run(
            pr_number, expected_commit_sha=commit_sha,
            step=-1, step_label="Error",
            error_message="Pipeline processing failed. Check structured service logs.",
        )
        raise
