"""Regression tests for scanner fail-closed behavior."""

from scan_models import ScanVerdict, ScannerResult, ScannerStatus, determine_verdict


def _success(scanner: str, findings=None):
    return ScannerResult(scanner, ScannerStatus.SUCCESS, findings or [])


def _complete(findings=None):
    return [
        _success("syntax"),
        _success("semgrep", findings),
        _success("claude"),
        _success("dependencies"),
        _success("malware"),
    ]


def test_all_scanners_must_be_present():
    assert determine_verdict([]) == ScanVerdict.SCAN_FAILED


def test_claude_failure_cannot_pass_when_semgrep_succeeds():
    results = _complete()
    results[2] = ScannerResult("claude", ScannerStatus.FAILED)
    assert determine_verdict(results) == ScanVerdict.SCAN_FAILED


def test_semgrep_failure_cannot_pass_when_claude_succeeds():
    results = _complete()
    results[1] = ScannerResult("semgrep", ScannerStatus.FAILED)
    assert determine_verdict(results) == ScanVerdict.SCAN_FAILED


def test_partial_scanner_requires_review():
    results = _complete()
    results[1] = ScannerResult("semgrep", ScannerStatus.PARTIAL)
    assert determine_verdict(results) == ScanVerdict.REVIEW_REQUIRED


def test_successful_empty_results_can_pass():
    assert determine_verdict(_complete()) == ScanVerdict.PASSED


def test_claude_not_applicable_can_pass_for_binary_only_artifact():
    results = _complete()
    results[2] = ScannerResult(
        "claude", ScannerStatus.SKIPPED,
        metadata={"not_applicable": True},
    )
    assert determine_verdict(results) == ScanVerdict.PASSED


def test_arbitrary_skipped_required_stage_cannot_pass():
    results = _complete()
    results[1] = ScannerResult(
        "semgrep", ScannerStatus.SKIPPED,
        metadata={"not_applicable": True},
    )
    assert determine_verdict(results) == ScanVerdict.REVIEW_REQUIRED


def test_unmapped_high_finding_is_blocking():
    finding = {
        "status": "FINDING", "severity": "HIGH", "confidence": 0.95,
        "mapped": False, "vulnerability_type": "UNSAFE_REFLECTION",
    }
    assert determine_verdict(_complete([finding])) == ScanVerdict.BLOCKED


def test_medium_finding_requires_review():
    finding = {"status": "FINDING", "severity": "MEDIUM", "confidence": 1.0}
    assert determine_verdict(_complete([finding])) == ScanVerdict.REVIEW_REQUIRED


def test_unverified_control_is_not_a_pass():
    finding = {"status": "NOT_VERIFIED", "severity": "INFO", "confidence": 1.0}
    assert determine_verdict(_complete([finding])) == ScanVerdict.REVIEW_REQUIRED


def test_critical_finding_is_blocked_even_when_another_scanner_failed():
    finding = {"status": "FINDING", "severity": "CRITICAL", "confidence": 1.0}
    results = _complete(finding and [finding])
    results[2] = ScannerResult("claude", ScannerStatus.FAILED)
    assert determine_verdict(results) == ScanVerdict.BLOCKED
