"""
main.py — Crucible FastAPI Webhook Server
==========================================
Receives GitHub PR webhooks, verifies HMAC, and durably queues the pipeline.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

HMAC note: hmac.new() takes positional args to avoid Python version differences:
    hmac.new(key, msg, digestmod)  — NOT hmac.new(key, msg=..., digestmod=...)

Unit tests for HMAC are in tests/test_hmac.py — run these before Day 5 integration.
"""

import asyncio
from contextlib import asynccontextmanager, suppress
import json
import os
import re

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

load_dotenv(dotenv_path=".env", override=False)

try:
    from .auth import validate_webhook_config, verify_signature
    from .pipeline import post_pipeline_failure, run_pipeline
    from .state import (
        claim_job,
        complete_job,
        enqueue_job,
        fail_expired_jobs,
        fail_job,
        healthcheck as db_healthcheck,
        init_db,
        job_counts,
        renew_job,
        retry_job,
    )
except ImportError:  # Support `cd crucible && uvicorn main:app`.
    from auth import validate_webhook_config, verify_signature
    from pipeline import post_pipeline_failure, run_pipeline
    from state import (
        claim_job,
        complete_job,
        enqueue_job,
        fail_expired_jobs,
        fail_job,
        healthcheck as db_healthcheck,
        init_db,
        job_counts,
        renew_job,
        retry_job,
    )

GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
GITHUB_OWNER   = os.environ.get("GITHUB_OWNER", "")
GITHUB_REPO    = os.environ.get("GITHUB_REPO", "")


def _positive_int_env(name: str, default: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    if not raw.isdigit():
        raise RuntimeError(f"{name} must be a positive integer")
    value = int(raw)
    if value < 1 or value > maximum:
        raise RuntimeError(f"{name} must be between 1 and {maximum}")
    return value


MAX_WEBHOOK_BODY_BYTES = _positive_int_env(
    "MAX_WEBHOOK_BODY_BYTES", 2 * 1024 * 1024, 10 * 1024 * 1024,
)


def validate_app_config() -> None:
    """Validate configuration needed to safely accept production webhook work."""
    validate_webhook_config()
    if os.environ.get("APP_ENV", "production").strip().lower() == "production":
        missing = [
            name for name, value in (
                ("GITHUB_TOKEN", GITHUB_TOKEN),
                ("GITHUB_OWNER", GITHUB_OWNER),
                ("GITHUB_REPO", GITHUB_REPO),
                ("DATABASE_URL", os.environ.get("DATABASE_URL", "")),
            )
            if not value.strip()
        ]
        if missing:
            raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")


pipeline_worker_task: asyncio.Task | None = None
WORKER_POLL_SECONDS = _positive_int_env("WORKER_POLL_SECONDS", 1, 60)
JOB_LEASE_SECONDS = _positive_int_env("JOB_LEASE_SECONDS", 900, 86_400)


# ── Background worker ─────────────────────────────────────────────────────

async def pipeline_worker() -> None:
    """Lease durable jobs one at a time, including work abandoned after a restart."""
    print("[Worker] Pipeline worker started")
    while True:
        abandoned = await asyncio.to_thread(fail_expired_jobs)
        for failed_job in abandoned:
            pr_number = int(failed_job["pr_number"])
            print(f"[Worker] PR #{pr_number} dead-lettered after worker loss")
            try:
                await post_pipeline_failure(
                    pr_number, str(failed_job["commit_sha"]),
                )
            except Exception:
                print(f"[Worker] Could not publish failure status for PR #{pr_number}")
        job = await asyncio.to_thread(claim_job, JOB_LEASE_SECONDS)
        if job is None:
            await asyncio.sleep(WORKER_POLL_SECONDS)
            continue
        delivery_id = str(job["delivery_id"])
        pr_number = int(job["pr_number"])
        commit_sha = str(job["commit_sha"])
        try:
            await _run_leased_job(job)
        except asyncio.CancelledError:
            raise
        except Exception:
            attempts = int(job["attempts"])
            max_attempts = int(job["max_attempts"])
            if attempts < max_attempts:
                delay = min(60, 2 ** attempts)
                await asyncio.to_thread(
                    retry_job, delivery_id, "PIPELINE_ATTEMPT_FAILED", delay,
                )
                print(
                    f"[Worker] PR #{pr_number} attempt {attempts}/{max_attempts} "
                    f"failed; retrying in {delay}s"
                )
            else:
                await asyncio.to_thread(
                    fail_job, delivery_id, "PIPELINE_RETRIES_EXHAUSTED",
                )
                print(f"[Worker] PR #{pr_number} failed after {attempts} attempts")
                try:
                    await post_pipeline_failure(pr_number, commit_sha)
                except Exception:
                    print(f"[Worker] Could not publish failure status for PR #{pr_number}")
        else:
            await asyncio.to_thread(complete_job, delivery_id)


async def _process_job(job: dict) -> None:
    expected_repo = f"{GITHUB_OWNER}/{GITHUB_REPO}".casefold()
    if str(job["repository"]).casefold() != expected_repo:
        raise RuntimeError("Persisted job repository does not match configuration")
    pr_number = int(job["pr_number"])
    files = await _fetch_pr_files(pr_number)
    _validate_changed_files(files)
    await run_pipeline(
        files=files,
        pr_number=pr_number,
        commit_sha=str(job["commit_sha"]),
    )


async def _run_leased_job(job: dict) -> None:
    """Stop processing before lease expiry if ownership cannot be renewed."""
    processing = asyncio.create_task(_process_job(job))
    heartbeat = asyncio.create_task(_renew_lease(str(job["delivery_id"])))
    try:
        done, _ = await asyncio.wait(
            {processing, heartbeat}, return_when=asyncio.FIRST_COMPLETED,
        )
        if processing in done:
            await processing
            return
        await heartbeat
        processing.cancel()
        with suppress(asyncio.CancelledError):
            await processing
        raise RuntimeError("Durable job lease could not be renewed")
    finally:
        heartbeat.cancel()
        processing.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat
        with suppress(asyncio.CancelledError):
            await processing


async def _renew_lease(delivery_id: str) -> None:
    """Keep ownership of long work; fail after bounded renewal errors."""
    interval = max(1, JOB_LEASE_SECONDS // 3)
    consecutive_failures = 0
    delay = interval
    while True:
        await asyncio.sleep(delay)
        try:
            renewed = await asyncio.to_thread(
                renew_job, delivery_id, JOB_LEASE_SECONDS,
            )
        except Exception:
            renewed = False
        if renewed:
            consecutive_failures = 0
            delay = interval
            continue
        consecutive_failures += 1
        if consecutive_failures >= 3:
            return
        delay = min(5, max(1, interval // 10))


# ── Startup / shutdown ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    global pipeline_worker_task
    validate_app_config()
    init_db()
    pipeline_worker_task = asyncio.create_task(pipeline_worker())
    print("[Crucible] Server started — pipeline worker running")
    try:
        yield
    finally:
        if pipeline_worker_task:
            pipeline_worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await pipeline_worker_task


app = FastAPI(title="Crucible Webhook Server", lifespan=lifespan)


async def _github_get(
    client: httpx.AsyncClient, url: str, **kwargs,
) -> httpx.Response:
    """Retry GitHub rate limits and transient server/network failures."""
    last_error: httpx.HTTPError | None = None
    for attempt in range(3):
        try:
            response = await client.get(url, **kwargs)
        except httpx.HTTPError as exc:
            last_error = exc
        else:
            if response.status_code != 429 and response.status_code < 500:
                return response
            if attempt == 2:
                return response
        await asyncio.sleep(0.25 * (2 ** attempt))
    if last_error:
        raise last_error
    raise RuntimeError("GitHub retry loop ended without a response")


# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> JSONResponse:
    worker_ok = pipeline_worker_task is not None and not pipeline_worker_task.done()
    database_ok = db_healthcheck()
    counts = await asyncio.to_thread(job_counts) if database_ok else {}
    status = "ok" if worker_ok and database_ok else "degraded"
    payload = {
        "status": status,
        "jobs": counts,
        "worker_ok": worker_ok,
        "database_ok": database_ok,
    }
    return JSONResponse(payload, status_code=200 if status == "ok" else 503)


@app.post("/webhook")
async def github_webhook(request: Request) -> JSONResponse:
    """
    Verify the webhook and atomically persist a minimal job before acknowledging it.
    """
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length")
        if declared_length < 0 or declared_length > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Webhook payload too large")
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Webhook payload too large")
    sig  = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(body, sig):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event  = request.headers.get("X-GitHub-Event", "")
    action = payload.get("action", "")
    delivery_id = request.headers.get("X-GitHub-Delivery", "")
    if not delivery_id:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Delivery")
    # Only process PR open/update events
    if event != "pull_request" or action not in ("opened", "synchronize"):
        return JSONResponse({"status": "ignored", "reason": f"event={event} action={action}"})

    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise HTTPException(status_code=400, detail="Missing repository identity")
    full_name = str(repository.get("full_name", "")).casefold()
    if full_name != f"{GITHUB_OWNER}/{GITHUB_REPO}".casefold():
        raise HTTPException(status_code=403, detail="Repository does not match configuration")

    pr = payload.get("pull_request", {})
    if not isinstance(pr, dict):
        raise HTTPException(status_code=400, detail="Malformed pull_request")
    pr_number = pr.get("number")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
        raise HTTPException(status_code=400, detail="pull_request.number must be a positive integer")
    commit_sha = str(pr.get("head", {}).get("sha", ""))
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha):
        raise HTTPException(status_code=400, detail="Missing or invalid pull-request head SHA")
    accepted = await asyncio.to_thread(
        enqueue_job, delivery_id, pr_number, commit_sha.lower(), full_name,
    )
    if not accepted:
        return JSONResponse({"status": "duplicate", "delivery_id": delivery_id})

    print(f"[Webhook] PR #{pr_number} durably queued")
    return JSONResponse(
        {"status": "accepted", "pr_number": pr_number},
        status_code=202,
    )


def _validate_changed_files(files: list[dict] | None) -> None:
    """Reject incomplete GitHub file data before starting expensive analysis."""
    if files is None:
        raise RuntimeError("Failed to fetch PR files from GitHub")
    if not files:
        raise RuntimeError("Pull request contains no changed files")
    incomplete = [
        item.get("filename", "unknown")
        for item in files
        if not isinstance(item.get("patch"), str)
    ]
    if incomplete:
        raise RuntimeError(
            f"GitHub omitted patch data for {len(incomplete)} changed file(s)"
        )


async def _fetch_pr_files(pr_number: int) -> list[dict] | None:
    """
    Fetch the list of changed files for a PR.
    Returns list of {filename, patch, status} dicts, or None on error.
    """
    missing = [v for v, val in [
        ("GITHUB_TOKEN", GITHUB_TOKEN),
        ("GITHUB_OWNER", GITHUB_OWNER),
        ("GITHUB_REPO",  GITHUB_REPO),
    ] if not val]
    if missing:
        print(f"[Webhook] {', '.join(missing)} not set — rejecting job")
        return None

    url = (
        f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
        f"/pulls/{pr_number}/files"
    )
    files: list[dict] = []
    async with httpx.AsyncClient() as client:
        for page in range(1, 31):
            resp = await _github_get(
                client,
                url,
                params={"per_page": 100, "page": page},
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=15,
            )
            if resp.status_code != 200:
                print(f"[Webhook] Failed to fetch PR files: HTTP {resp.status_code}")
                return None
            batch = resp.json()
            if not isinstance(batch, list):
                return None
            if any(
                not isinstance(item, dict)
                or not isinstance(item.get("filename"), str)
                or item.get("status") not in {"added", "modified", "removed", "renamed", "changed", "copied"}
                for item in batch
            ):
                return None
            files.extend(batch)
            if len(batch) < 100:
                return files
    print("[Webhook] PR file pagination exceeded the 3,000-file safety limit")
    return None
