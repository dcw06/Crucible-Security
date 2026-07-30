"""Mandatory merge evidence and real requirement-marker tests."""

from confidence import compute_confidence
from pipeline import _requirement_marker_counts


def _high_confidence(**overrides):
    values = {
        "iteration": 1,
        "warnings": 0,
        "errors": 0,
        "any_critical": False,
        "tc_pass_rate": 1.0,
    }
    values.update(overrides)
    return compute_confidence(**values)


def test_critic_rejection_blocks_even_with_perfect_numeric_score():
    result = _high_confidence(critic_approved=False)
    assert result.confidence == 1.0
    assert result.gate == "BLOCKED"


def test_missing_attested_sandbox_result_cannot_approve():
    assert _high_confidence(sandbox_verified=False).gate == "REVIEW"


def test_unverified_requirement_coverage_cannot_approve():
    assert _high_confidence(coverage_verified=False).gate == "REVIEW"


def test_attested_sandbox_failures_block_when_test_cloud_is_unavailable():
    result = _high_confidence(
        tc_pass_rate=None,
        execution_pass_rate=0.5,
        sandbox_tests_passed=False,
    )
    assert result.confidence == 0.8
    assert result.gate == "BLOCKED"


def test_attested_sandbox_rate_is_authoritative_over_test_cloud():
    result = _high_confidence(tc_pass_rate=1.0, execution_pass_rate=0.25)
    assert result.confidence == 0.7


def test_requirement_coverage_is_derived_from_literal_markers():
    code = '''
import pytest

@pytest.mark.req_id("REQ-001")
def test_one():
    pass

@pytest.mark.req_id("REQ-001")
def test_two():
    pass

@pytest.mark.req_id("REQ-002")
def test_three():
    pass
'''
    assert _requirement_marker_counts(code) == {"REQ-001": 2, "REQ-002": 1}


def test_dynamic_or_malformed_markers_are_not_counted():
    code = '''
import pytest
name = "REQ-001"

@pytest.mark.req_id(name)
def test_dynamic():
    pass
'''
    assert _requirement_marker_counts(code) == {}
