"""Scanner startup-preload contracts."""

import json

import scanner_preload


def test_preload_writes_snapshot_atomically(monkeypatch, tmp_path):
    expected = {
        "semgrep": {"available": True, "version": "1.2.3", "error": ""},
    }
    monkeypatch.setattr(scanner_preload, "check_scanner_readiness", lambda: expected)
    path = tmp_path / "readiness.json"

    assert scanner_preload.preload_scanner_readiness(path) == expected
    assert scanner_preload.load_preloaded_scanner_readiness(path) == expected
    assert json.loads(path.read_text())["generated_at"]


def test_invalid_or_missing_snapshot_falls_back(tmp_path):
    path = tmp_path / "readiness.json"
    assert scanner_preload.load_preloaded_scanner_readiness(path) is None
    path.write_text('{"readiness":{"semgrep":{"available":"yes"}}}')
    assert scanner_preload.load_preloaded_scanner_readiness(path) is None


def test_nullable_success_metadata_is_normalized(tmp_path):
    path = tmp_path / "readiness.json"
    path.write_text(
        '{"readiness":{"clamscan":{'
        '"available":true,"version":"1.0","error":null}}}'
    )
    assert scanner_preload.load_preloaded_scanner_readiness(path) == {
        "clamscan": {"available": True, "version": "1.0", "error": ""},
    }
