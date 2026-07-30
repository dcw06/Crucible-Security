"""Controlled-failure tests for the historical Python model demos."""

from types import SimpleNamespace
import json

import pytest

import code_pipeline
import research_pipeline


def test_code_pipeline_finds_text_after_non_text_block():
    response = SimpleNamespace(content=[
        SimpleNamespace(type="thinking"),
        SimpleNamespace(type="text", text="  result  "),
    ])
    assert code_pipeline._first_text(response, "Writer") == "result"


def test_code_pipeline_rejects_missing_text():
    with pytest.raises(RuntimeError, match="no text content"):
        code_pipeline._first_text(SimpleNamespace(content=[]), "Writer")


def test_research_agent_rejects_empty_end_turn(monkeypatch):
    monkeypatch.setattr(
        research_pipeline.client.messages,
        "create",
        lambda **_: SimpleNamespace(stop_reason="end_turn", content=[]),
    )
    with pytest.raises(RuntimeError, match="no text content"):
        research_pipeline.run_agent("system", "question")


def test_synthesis_requires_majority_of_researchers():
    failed = [
        {
            "subtopic": {"id": str(index), "title": "topic", "query": "query"},
            "status": "failed",
            "error_code": "RESEARCHER_FAILED",
        }
        for index in range(3)
    ]
    with pytest.raises(RuntimeError, match="Insufficient research results"):
        research_pipeline.synthesize("question", failed)


def test_web_search_requires_live_provider(monkeypatch):
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="BRAVE_SEARCH_API_KEY"):
        research_pipeline.web_search("solid-state batteries")


def test_web_search_returns_deduplicated_provenance(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return json.dumps({
                "web": {
                    "results": [
                        {
                            "title": "Primary source",
                            "url": "https://example.test/paper",
                            "description": "Evidence",
                            "age": "2026-01-01",
                        },
                        {
                            "title": "Duplicate",
                            "url": "https://example.test/paper",
                            "description": "Duplicate evidence",
                        },
                    ],
                },
            }).encode()

    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-key")
    monkeypatch.setattr(research_pipeline, "urlopen", lambda *_args, **_kwargs: Response())
    result = json.loads(research_pipeline.web_search("  batteries  "))
    assert result["provider"] == "Brave Search"
    assert result["query"] == "batteries"
    assert result["retrieved_at"].endswith("+00:00")
    assert result["results"] == [{
        "title": "Primary source",
        "url": "https://example.test/paper",
        "description": "Evidence",
        "published": "2026-01-01",
    }]
