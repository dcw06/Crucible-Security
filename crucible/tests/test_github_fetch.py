"""GitHub PR retrieval must fail closed when repository identity is missing."""

import asyncio

import main


def test_missing_github_configuration_returns_no_files(monkeypatch):
    monkeypatch.setattr(main, "GITHUB_TOKEN", "")
    monkeypatch.setattr(main, "GITHUB_OWNER", "")
    monkeypatch.setattr(main, "GITHUB_REPO", "")
    assert asyncio.run(main._fetch_pr_files(1)) is None
