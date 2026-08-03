"""
state/db.py — Shared State (PostgreSQL or SQLite)
==================================================
Written by FastAPI webhook worker; read by Streamlit dashboard.

On Render (or any cloud deploy), set DATABASE_URL to a PostgreSQL connection
string — both the webhook and dashboard services connect to the same DB.

Locally, leave DATABASE_URL unset and SQLite is used instead
(file path from STATE_DB env var, defaults to /tmp/crucible_state.db).

Render sets DATABASE_URL automatically when you attach a PostgreSQL database
to a service — just add the same env var to both the webhook and dashboard
services in the Render dashboard.
"""

import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from urllib.parse import urlsplit
from pathlib import Path

# ── Backend detection ─────────────────────────────────────────────────────

DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_PATH = Path(
    os.environ.get("STATE_DB", str(Path(tempfile.gettempdir()) / "crucible_state.db"))
)

# Render's DATABASE_URL uses "postgres://" — psycopg2 requires "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    parsed = urlsplit(DATABASE_URL)
    location = parsed.hostname or "configured host"
    database = parsed.path.lstrip("/") or "configured database"
    print(f"[DB] Using PostgreSQL ({location}/{database})")
else:
    print(f"[DB] Using SQLite ({DB_PATH})")


PIPELINE_STEPS = [
    "Queued",
    "PR files fetched",
    "Requirements analyzed",
    "Tests generated (Writer)",
    "Tests reviewed (Critic)",
    "Security scanned (Semgrep)",
    "pytest executed",
    "Results uploaded to TC",
    "TC run polled & scored",
    "Complete",
]

# ── DDL ───────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS pipeline_runs (
        pr_number     INTEGER PRIMARY KEY,
        step          INTEGER DEFAULT 0,
        step_label    TEXT    DEFAULT 'Queued',
        confidence    REAL,
        tc_pass_rate  REAL,
        execution_pass_rate REAL,
        commit_sha    TEXT,
        findings      TEXT,
        req_coverage  TEXT,
        fragile_count INTEGER DEFAULT 0,
        security_summary TEXT,
        gate          TEXT,
        error_message TEXT,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

_CREATE_DELIVERIES_TABLE = """
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
        delivery_id TEXT PRIMARY KEY,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

_CREATE_JOBS_TABLE = """
    CREATE TABLE IF NOT EXISTS pipeline_jobs (
        delivery_id  TEXT PRIMARY KEY,
        pr_number    INTEGER NOT NULL,
        commit_sha   TEXT NOT NULL,
        repository  TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'QUEUED',
        attempts     INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        available_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        lease_until  TIMESTAMP,
        last_error   TEXT,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

_CREATE_UPLOAD_HISTORY_TABLE = """
    CREATE TABLE IF NOT EXISTS upload_scan_history (
        scan_id       TEXT PRIMARY KEY,
        target_type   TEXT NOT NULL,
        target_name   TEXT NOT NULL,
        verdict       TEXT NOT NULL,
        reason        TEXT NOT NULL,
        files_scanned INTEGER NOT NULL DEFAULT 0,
        finding_count INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        high_count    INTEGER NOT NULL DEFAULT 0,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


# ── Connection helpers ────────────────────────────────────────────────────

def _pg_conn():
    """Open a new psycopg2 connection."""
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def _sqlite_conn():
    """Open a new sqlite3 connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# ── Public API ────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create the pipeline_runs table if it doesn't exist."""
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(_CREATE_TABLE)
                cur.execute(_CREATE_DELIVERIES_TABLE)
                cur.execute(_CREATE_JOBS_TABLE)
                cur.execute(_CREATE_UPLOAD_HISTORY_TABLE)
                cur.execute(
                    "ALTER TABLE pipeline_runs "
                    "ADD COLUMN IF NOT EXISTS execution_pass_rate REAL"
                )
                cur.execute(
                    "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS commit_sha TEXT"
                )
    else:
        with _sqlite_conn() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_DELIVERIES_TABLE)
            conn.execute(_CREATE_JOBS_TABLE)
            conn.execute(_CREATE_UPLOAD_HISTORY_TABLE)
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(pipeline_runs)").fetchall()
            }
            if "execution_pass_rate" not in columns:
                conn.execute(
                    "ALTER TABLE pipeline_runs ADD COLUMN execution_pass_rate REAL"
                )
            if "commit_sha" not in columns:
                conn.execute("ALTER TABLE pipeline_runs ADD COLUMN commit_sha TEXT")


def upsert_run(
    pr_number: int, *, expected_commit_sha: str | None = None, **kwargs,
) -> None:
    """Insert or update a pipeline run record. Pass any column=value kwargs."""
    # Serialize JSON fields
    for key in ("findings", "req_coverage"):
        if key in kwargs and not isinstance(kwargs[key], str):
            kwargs[key] = json.dumps(kwargs[key])

    if expected_commit_sha is not None:
        set_clause = ", ".join(f"{key}=%s" for key in kwargs)
        values = list(kwargs.values())
        if USE_POSTGRES:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        UPDATE pipeline_runs
                        SET {set_clause}, updated_at=CURRENT_TIMESTAMP
                        WHERE pr_number=%s AND commit_sha=%s
                        """,
                        values + [pr_number, expected_commit_sha],
                    )
        else:
            sqlite_set_clause = ", ".join(f"{key}=?" for key in kwargs)
            with _sqlite_conn() as conn:
                conn.execute(
                    f"""
                    UPDATE pipeline_runs
                    SET {sqlite_set_clause}, updated_at=CURRENT_TIMESTAMP
                    WHERE pr_number=? AND commit_sha=?
                    """,
                    values + [pr_number, expected_commit_sha],
                )
        return

    if USE_POSTGRES:
        cols        = list(kwargs.keys())
        vals        = list(kwargs.values())
        col_list    = ", ".join(cols)
        placeholder = ", ".join(["%s"] * len(cols))
        # Use EXCLUDED.col syntax so we don't need to repeat values
        set_clause  = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols)
        sql = f"""
            INSERT INTO pipeline_runs (pr_number, {col_list})
            VALUES (%s, {placeholder})
            ON CONFLICT (pr_number) DO UPDATE SET
                {set_clause},
                updated_at=CURRENT_TIMESTAMP
        """
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, [pr_number] + vals)
    else:
        set_clause = ", ".join(f"{k}=?" for k in kwargs)
        values     = list(kwargs.values())
        sql = f"""
            INSERT INTO pipeline_runs (pr_number, {', '.join(kwargs.keys())})
            VALUES (?, {', '.join('?' * len(kwargs))})
            ON CONFLICT(pr_number) DO UPDATE SET
                {set_clause},
                updated_at=CURRENT_TIMESTAMP
        """
        with _sqlite_conn() as conn:
            conn.execute(sql, [pr_number] + values + values)


def update_step(
    pr_number: int, step: int, label: str, commit_sha: str | None = None,
) -> None:
    """Advance the pipeline step indicator. Label is always required —
    the PIPELINE_STEPS list uses 0-based indexing and must not be used
    as a fallback for 1-based step numbers (would give wrong labels)."""
    upsert_run(
        pr_number, expected_commit_sha=commit_sha, step=step, step_label=label,
    )


def get_run(pr_number: int) -> dict | None:
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM pipeline_runs WHERE pr_number = %s",
                    (pr_number,)
                )
                row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
    else:
        with _sqlite_conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM pipeline_runs WHERE pr_number = ?",
                (pr_number,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)

    # Deserialize JSON fields — use type-correct fallbacks on parse failure
    _fallbacks = {"findings": [], "req_coverage": {}}
    for key, fallback in _fallbacks.items():
        raw = d.get(key)
        if raw:
            try:
                d[key] = json.loads(raw)
            except Exception:
                d[key] = fallback
    return d


def list_runs() -> list[dict]:
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM pipeline_runs ORDER BY updated_at DESC LIMIT 20"
                )
                rows = cur.fetchall()
        return [dict(r) for r in rows]
    with _sqlite_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY updated_at DESC LIMIT 20"
        ).fetchall()
    return [dict(r) for r in rows]


def record_upload_scan(
    scan_id: str,
    target_type: str,
    target_name: str,
    verdict: str,
    reason: str,
    files_scanned: int,
    finding_count: int,
    critical_count: int,
    high_count: int,
) -> None:
    """Persist a bounded scan summary; uploaded content is never stored."""
    values = (
        scan_id, target_type[:50], target_name[:500], verdict[:50],
        reason[:2_000], files_scanned, finding_count, critical_count, high_count,
    )
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO upload_scan_history (
                        scan_id, target_type, target_name, verdict, reason,
                        files_scanned, finding_count, critical_count, high_count
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id) DO NOTHING
                    """,
                    values,
                )
    else:
        with _sqlite_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO upload_scan_history (
                    scan_id, target_type, target_name, verdict, reason,
                    files_scanned, finding_count, critical_count, high_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )


def list_upload_scans(limit: int = 20) -> list[dict]:
    """Return recent upload summaries without source, evidence, or secrets."""
    bounded_limit = max(1, min(int(limit), 100))
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT * FROM upload_scan_history
                    ORDER BY created_at DESC LIMIT %s
                    """,
                    (bounded_limit,),
                )
                return [dict(row) for row in cur.fetchall()]
    with _sqlite_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT * FROM upload_scan_history
            ORDER BY created_at DESC LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
        return [dict(row) for row in rows]
def healthcheck() -> bool:
    """Verify that the configured state database accepts a trivial query."""
    try:
        if USE_POSTGRES:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return cur.fetchone()[0] == 1
        with _sqlite_conn() as conn:
            return conn.execute("SELECT 1").fetchone()[0] == 1
    except Exception:
        return False


def enqueue_job(
    delivery_id: str, pr_number: int, commit_sha: str, repository: str,
) -> bool:
    """Atomically deduplicate and persist a recoverable webhook job."""
    values = (delivery_id, pr_number, commit_sha, repository)
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO pipeline_jobs
                        (delivery_id, pr_number, commit_sha, repository)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING delivery_id
                    """,
                    values,
                )
                inserted = cur.fetchone() is not None
                if inserted:
                    cur.execute(
                        """
                        INSERT INTO pipeline_runs
                            (pr_number, step, step_label, commit_sha)
                        VALUES (%s, 0, 'Queued', %s)
                        ON CONFLICT (pr_number) DO UPDATE SET
                            step=0, step_label='Queued',
                            commit_sha=EXCLUDED.commit_sha,
                            error_message=NULL,
                            updated_at=CURRENT_TIMESTAMP
                        """,
                        (pr_number, commit_sha),
                    )
                return inserted
    with _sqlite_conn() as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO pipeline_jobs
                (delivery_id, pr_number, commit_sha, repository)
            VALUES (?, ?, ?, ?)
            """,
            values,
        )
        inserted = cursor.rowcount == 1
        if inserted:
            conn.execute(
                """
                INSERT INTO pipeline_runs
                    (pr_number, step, step_label, commit_sha)
                VALUES (?, 0, 'Queued', ?)
                ON CONFLICT(pr_number) DO UPDATE SET
                    step=0, step_label='Queued',
                    commit_sha=excluded.commit_sha,
                    error_message=NULL,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (pr_number, commit_sha),
            )
        return inserted


def claim_job(lease_seconds: int = 300) -> dict | None:
    """Lease one available job and reclaim work abandoned by a dead worker."""
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    WITH candidate AS (
                        SELECT delivery_id
                        FROM pipeline_jobs
                        WHERE attempts < max_attempts
                          AND available_at <= CURRENT_TIMESTAMP
                          AND (
                            status IN ('QUEUED', 'RETRY')
                            OR (status = 'LEASED' AND lease_until <= CURRENT_TIMESTAMP)
                          )
                        ORDER BY created_at
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE pipeline_jobs AS job
                    SET status='LEASED',
                        attempts=attempts + 1,
                        lease_until=CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        updated_at=CURRENT_TIMESTAMP
                    FROM candidate
                    WHERE job.delivery_id = candidate.delivery_id
                    RETURNING job.*
                    """,
                    (lease_seconds,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
    with _sqlite_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT * FROM pipeline_jobs
            WHERE attempts < max_attempts
              AND available_at <= CURRENT_TIMESTAMP
              AND (
                status IN ('QUEUED', 'RETRY')
                OR (status = 'LEASED' AND lease_until <= CURRENT_TIMESTAMP)
              )
            ORDER BY created_at
            LIMIT 1
            """
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            UPDATE pipeline_jobs
            SET status='LEASED',
                attempts=attempts + 1,
                lease_until=datetime('now', ?),
                updated_at=CURRENT_TIMESTAMP
            WHERE delivery_id=?
            """,
            (f"+{lease_seconds} seconds", row["delivery_id"]),
        )
        claimed = dict(row)
        claimed["attempts"] = int(row["attempts"]) + 1
        claimed["status"] = "LEASED"
        return claimed


def complete_job(delivery_id: str) -> None:
    _set_job_status(delivery_id, "COMPLETED", None, 0)


def renew_job(delivery_id: str, lease_seconds: int) -> bool:
    """Extend an active lease so another replica cannot duplicate long work."""
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE pipeline_jobs
                    SET lease_until=CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        updated_at=CURRENT_TIMESTAMP
                    WHERE delivery_id=%s AND status='LEASED'
                    """,
                    (lease_seconds, delivery_id),
                )
                return cur.rowcount == 1
    else:
        with _sqlite_conn() as conn:
            cursor = conn.execute(
                """
                UPDATE pipeline_jobs
                SET lease_until=datetime('now', ?), updated_at=CURRENT_TIMESTAMP
                WHERE delivery_id=? AND status='LEASED'
                """,
                (f"+{lease_seconds} seconds", delivery_id),
            )
            return cursor.rowcount == 1


def fail_expired_jobs() -> list[dict]:
    """Dead-letter final-attempt leases abandoned by crashed workers."""
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE pipeline_jobs
                    SET status='FAILED',
                        last_error='PIPELINE_WORKER_LOST',
                        lease_until=NULL,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE status='LEASED'
                      AND lease_until <= CURRENT_TIMESTAMP
                      AND attempts >= max_attempts
                    RETURNING *
                    """
                )
                return [dict(row) for row in cur.fetchall()]
    with _sqlite_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT * FROM pipeline_jobs
            WHERE status='LEASED'
              AND lease_until <= CURRENT_TIMESTAMP
              AND attempts >= max_attempts
            """
        ).fetchall()
        if rows:
            conn.execute(
                """
                UPDATE pipeline_jobs
                SET status='FAILED',
                    last_error='PIPELINE_WORKER_LOST',
                    lease_until=NULL,
                    updated_at=CURRENT_TIMESTAMP
                WHERE status='LEASED'
                  AND lease_until <= CURRENT_TIMESTAMP
                  AND attempts >= max_attempts
                """
            )
        return [dict(row) for row in rows]


def retry_job(delivery_id: str, error_code: str, delay_seconds: int) -> None:
    _set_job_status(delivery_id, "RETRY", error_code, delay_seconds)


def fail_job(delivery_id: str, error_code: str) -> None:
    _set_job_status(delivery_id, "FAILED", error_code, 0)


def _set_job_status(
    delivery_id: str, status: str, error_code: str | None, delay_seconds: int,
) -> None:
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE pipeline_jobs
                    SET status=%s, last_error=%s, lease_until=NULL,
                        available_at=CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        updated_at=CURRENT_TIMESTAMP
                    WHERE delivery_id=%s
                    """,
                    (status, error_code, delay_seconds, delivery_id),
                )
    else:
        with _sqlite_conn() as conn:
            conn.execute(
                """
                UPDATE pipeline_jobs
                SET status=?, last_error=?, lease_until=NULL,
                    available_at=datetime('now', ?),
                    updated_at=CURRENT_TIMESTAMP
                WHERE delivery_id=?
                """,
                (status, error_code, f"+{delay_seconds} seconds", delivery_id),
            )


def job_counts() -> dict[str, int]:
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status, COUNT(*) FROM pipeline_jobs GROUP BY status")
                return {str(status): int(count) for status, count in cur.fetchall()}
    with _sqlite_conn() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) FROM pipeline_jobs GROUP BY status"
        ).fetchall()
    return {str(status): int(count) for status, count in rows}


def reserve_delivery(delivery_id: str) -> bool:
    """Atomically reserve a GitHub delivery across workers and instances."""
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO webhook_deliveries (delivery_id) VALUES (%s) "
                    "ON CONFLICT DO NOTHING RETURNING delivery_id",
                    (delivery_id,),
                )
                return cur.fetchone() is not None
    with _sqlite_conn() as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO webhook_deliveries (delivery_id) VALUES (?)",
            (delivery_id,),
        )
        return cursor.rowcount == 1


def release_delivery(delivery_id: str) -> None:
    """Release a failed admission so GitHub can retry the delivery."""
    if USE_POSTGRES:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM webhook_deliveries WHERE delivery_id = %s",
                    (delivery_id,),
                )
    else:
        with _sqlite_conn() as conn:
            conn.execute(
                "DELETE FROM webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            )


# Auto-init on import
init_db()
