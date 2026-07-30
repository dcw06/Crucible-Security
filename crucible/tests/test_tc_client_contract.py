"""Local Test Cloud input-contract tests."""

import asyncio
from pathlib import Path

import pytest

from tc_client import (
    _finish_execution, _get_stats, _record_test_result, parse_junit_xml,
)


def test_junit_identity_uses_classname_and_name(tmp_path: Path):
    xml = tmp_path / "results.xml"
    xml.write_text(
        '<testsuite><testcase classname="pkg.One" name="test_same"/>'
        '<testcase classname="pkg.Two" name="test_same"/></testsuite>',
        encoding="utf-8",
    )
    assert [item["name"] for item in parse_junit_xml(str(xml))] == [
        "pkg.One::test_same",
        "pkg.Two::test_same",
    ]


def test_duplicate_junit_identity_is_rejected(tmp_path: Path):
    xml = tmp_path / "results.xml"
    xml.write_text(
        '<testsuite><testcase classname="pkg.One" name="test_same"/>'
        '<testcase classname="pkg.One" name="test_same"/></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate JUnit test identity"):
        parse_junit_xml(str(xml))


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = ""

    def json(self):
        return self._payload


def test_log_start_failure_aborts_result_recording():
    class Client:
        def __init__(self):
            self.calls = 0

        async def post(self, *_args, **_kwargs):
            self.calls += 1
            return (
                _Response(201, {"id": "log"})
                if self.calls == 1 else _Response(500)
            )

    assert asyncio.run(
        _record_test_result(Client(), "execution", "case", True)
    ) is False


def test_stats_must_match_expected_junit_total():
    class Client:
        async def get(self, *_args, **_kwargs):
            return _Response(200, {"passed": 1, "failed": 0, "none": 0})

    assert asyncio.run(_get_stats(Client(), "execution", expected_total=2)) is None


def test_stats_reject_boolean_counts():
    class Client:
        async def get(self, *_args, **_kwargs):
            return _Response(200, {"passed": True, "failed": 0, "none": 0})

    assert asyncio.run(_get_stats(Client(), "execution", expected_total=1)) is None


def test_finish_reconciles_already_finalized_execution():
    class Client:
        async def post(self, *_args, **_kwargs):
            return _Response(
                400,
                {
                    "errorCode": "testExecutionAlreadyStarted",
                    "errorMessage": "TestExecution has already started.",
                },
            )

        async def get(self, *_args, **_kwargs):
            return _Response(200, {"status": "Finished"})

    assert asyncio.run(_finish_execution(Client(), "execution")) is True


def test_finish_does_not_hide_nonterminal_transition_error():
    class Client:
        async def post(self, *_args, **_kwargs):
            return _Response(400, {"errorCode": "invalidTransition"})

        async def get(self, *_args, **_kwargs):
            return _Response(200, {"status": "Running"})

    assert asyncio.run(_finish_execution(Client(), "execution")) is False
