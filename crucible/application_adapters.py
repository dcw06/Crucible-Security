"""Common contracts for platform-specific application test targets."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TargetKind(str, Enum):
    WEB = "WEB"
    WINDOWS_DESKTOP = "WINDOWS_DESKTOP"
    MAC_DESKTOP = "MAC_DESKTOP"
    LINUX_DESKTOP = "LINUX_DESKTOP"


class EvidenceStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"


@dataclass(frozen=True)
class ApplicationTarget:
    kind: TargetKind
    locator: str
    display_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TestStep:
    action: str
    target: str = ""
    value: str = ""


@dataclass(frozen=True)
class PlannedTest:
    test_id: str
    requirement_id: str
    title: str
    steps: tuple[TestStep, ...] = ()
    destructive: bool = False


@dataclass(frozen=True)
class TestPlan:
    tests: tuple[PlannedTest, ...]
    allowed_hosts: tuple[str, ...]
    browsers: tuple[str, ...] = ("chromium",)
    capture_trace: bool = True
    capture_screenshots: bool = True
    capture_video: bool = False


@dataclass(frozen=True)
class EvidenceArtifact:
    kind: str
    name: str
    sha256: str
    media_type: str
    size_bytes: int
    download_url: str | None = None
    content: bytes | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class NormalizedTestResult:
    test_id: str
    requirement_id: str
    status: EvidenceStatus
    severity: str = "INFO"
    confidence: float = 1.0
    detail: str = ""
    duration_ms: int = 0
    artifacts: tuple[EvidenceArtifact, ...] = ()
    console_errors: tuple[str, ...] = ()
    network_failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceBundle:
    target: ApplicationTarget
    results: tuple[NormalizedTestResult, ...]
    junit_xml: bytes
    verified: bool
    sandbox_id: str = ""
    isolation: dict[str, Any] = field(default_factory=dict)
    accessibility_findings: tuple[dict[str, Any], ...] = ()
    passive_findings: tuple[dict[str, Any], ...] = ()
    infrastructure_errors: tuple[str, ...] = ()

    @property
    def pass_rate(self) -> float | None:
        executed = [
            result for result in self.results
            if result.status in {EvidenceStatus.PASSED, EvidenceStatus.FAILED}
        ]
        if not self.verified or not executed:
            return None
        passed = sum(result.status == EvidenceStatus.PASSED for result in executed)
        return passed / len(executed)


class ApplicationAdapter(ABC):
    @abstractmethod
    def inspect(self, target: ApplicationTarget) -> Any:
        """Perform non-executing inspection of a target."""

    @abstractmethod
    def generate_tests(
        self,
        target: ApplicationTarget,
        requirements: list[dict[str, Any]],
    ) -> TestPlan:
        """Create a bounded, declarative test plan."""

    @abstractmethod
    def execute(
        self,
        target: ApplicationTarget,
        test_plan: TestPlan,
    ) -> EvidenceBundle:
        """Execute only through the adapter's configured sandbox boundary."""

    @abstractmethod
    def collect_evidence(self) -> EvidenceBundle | None:
        """Return the most recent normalized evidence bundle."""
