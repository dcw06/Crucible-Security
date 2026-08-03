"""SQLite state-history regression tests."""

from state import db


def test_sqlite_creates_configured_parent_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    database = tmp_path / "missing" / "state.db"
    monkeypatch.setattr(db, "DB_PATH", database)

    db.init_db()

    assert database.is_file()


def test_sqlite_list_runs_returns_recent_rows(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    db.upsert_run(42, step=10, step_label="Complete", gate="APPROVED")
    runs = db.list_runs()
    assert isinstance(runs, list)
    assert len(runs) == 1
    assert runs[0]["pr_number"] == 42
    assert runs[0]["gate"] == "APPROVED"


def test_sqlite_schema_migrates_execution_pass_rate(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    db.upsert_run(1, execution_pass_rate=0.75)
    assert db.get_run(1)["execution_pass_rate"] == 0.75


def test_upload_scan_history_persists_summary_only(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    db.record_upload_scan(
        "scan-1", "Desktop app", "sample.zip", "REVIEW_REQUIRED",
        "Native evidence is required", 12, 3, 1, 1,
    )
    rows = db.list_upload_scans()
    assert rows[0]["scan_id"] == "scan-1"
    assert rows[0]["target_name"] == "sample.zip"
    assert rows[0]["finding_count"] == 3
    assert "content" not in rows[0]


def test_delivery_reservation_is_atomic_and_releasable(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    assert db.reserve_delivery("delivery-1") is True
    assert db.reserve_delivery("delivery-1") is False
    db.release_delivery("delivery-1")
    assert db.reserve_delivery("delivery-1") is True


def test_durable_job_deduplicates_and_completes(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    args = ("delivery-1", 42, "a" * 40, "owner/repo")
    assert db.enqueue_job(*args) is True
    assert db.enqueue_job(*args) is False
    job = db.claim_job()
    assert job["delivery_id"] == "delivery-1"
    assert job["attempts"] == 1
    db.complete_job("delivery-1")
    assert db.claim_job() is None
    assert db.job_counts() == {"COMPLETED": 1}


def test_expired_job_lease_is_reclaimed_after_restart(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    db.enqueue_job("delivery-2", 7, "b" * 40, "owner/repo")
    assert db.claim_job(lease_seconds=0)["attempts"] == 1
    reclaimed = db.claim_job()
    assert reclaimed["delivery_id"] == "delivery-2"
    assert reclaimed["attempts"] == 2


def test_expired_final_attempt_is_dead_lettered(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    db.enqueue_job("delivery-3", 8, "c" * 40, "owner/repo")
    for attempt in range(1, 4):
        claimed = db.claim_job(lease_seconds=0)
        assert claimed["attempts"] == attempt
        if attempt < 3:
            db.retry_job("delivery-3", "TEST_FAILURE", 0)
    failed = db.fail_expired_jobs()
    assert [job["delivery_id"] for job in failed] == ["delivery-3"]
    assert db.job_counts() == {"FAILED": 1}


def test_older_commit_cannot_overwrite_newer_run(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.db")
    db.init_db()
    old_sha = "d" * 40
    new_sha = "e" * 40
    db.enqueue_job("delivery-old", 12, old_sha, "owner/repo")
    db.enqueue_job("delivery-new", 12, new_sha, "owner/repo")
    db.upsert_run(
        12, expected_commit_sha=old_sha,
        step=-1, step_label="Superseded",
    )
    current = db.get_run(12)
    assert current["commit_sha"] == new_sha
    assert current["step_label"] == "Queued"
    db.update_step(12, 10, "Complete", new_sha)
    assert db.get_run(12)["step_label"] == "Complete"
