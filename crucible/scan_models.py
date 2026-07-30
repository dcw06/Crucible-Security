"""Typed scanner results and conservative verdict policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScannerStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class ScanVerdict(str, Enum):
    PASSED = "PASSED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    SCAN_FAILED = "SCAN_FAILED"


@dataclass
class SecurityFinding:
    title: str
    vulnerability_type: str
    severity: str
    confidence: float
    evidence: str
    file_path: str | None = None
    line_number: int | None = None
    product_control_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    source: str = ""
    mapped: bool = False
    recommendation: str = ""
    status: str = "FINDING"
    original_category: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "product_control_ids": self.product_control_ids,
            "cwe_ids": self.cwe_ids,
            "source": self.source,
            "mapped": self.mapped,
            "recommendation": self.recommendation,
            "status": self.status,
            "original_category": self.original_category,
        }


@dataclass
class ScannerResult:
    scanner: str
    status: ScannerStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def determine_verdict(results: list[ScannerResult]) -> ScanVerdict:
    required = {"syntax", "semgrep", "claude", "dependencies", "malware"}
    present = {result.scanner for result in results}
    if required - present:
        return ScanVerdict.SCAN_FAILED
    required_results = [result for result in results if result.scanner in required]

    findings = [
        finding for result in results for finding in result.findings
        if str(finding.get("status", "FINDING")).upper() == "FINDING"
    ]
    if any(
        str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
        and float(finding.get("confidence", 1.0)) >= 0.7
        for finding in findings
    ):
        return ScanVerdict.BLOCKED

    if any(result.status == ScannerStatus.FAILED for result in required_results):
        return ScanVerdict.SCAN_FAILED
    def stage_satisfied(result: ScannerResult) -> bool:
        return result.status == ScannerStatus.SUCCESS or (
            result.status == ScannerStatus.SKIPPED
            and result.metadata.get("not_applicable") is True
            and result.scanner in {"claude"}
        )

    if any(not stage_satisfied(result) for result in required_results):
        return ScanVerdict.REVIEW_REQUIRED
    if any(
        str(finding.get("status", "")).upper() in {"REVIEW_REQUIRED", "NOT_VERIFIED"}
        or str(finding.get("severity", "")).upper() == "MEDIUM"
        for result in results for finding in result.findings
    ):
        return ScanVerdict.REVIEW_REQUIRED
    return ScanVerdict.PASSED
