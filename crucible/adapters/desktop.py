"""Normalized adapters for attested Windows, macOS, and Linux inspection."""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    from ..application_adapters import (
        ApplicationAdapter, ApplicationTarget, EvidenceBundle, EvidenceStatus,
        NormalizedTestResult, PlannedTest, TargetKind, TestPlan, TestStep,
    )
    from ..desktop_sandbox import inspect_native_artifact
    from ..scan_models import ScannerStatus
except ImportError:
    from application_adapters import (
        ApplicationAdapter, ApplicationTarget, EvidenceBundle, EvidenceStatus,
        NormalizedTestResult, PlannedTest, TargetKind, TestPlan, TestStep,
    )
    from desktop_sandbox import inspect_native_artifact
    from scan_models import ScannerStatus


PLATFORMS = {
    TargetKind.WINDOWS_DESKTOP: "Windows",
    TargetKind.MAC_DESKTOP: "macOS",
    TargetKind.LINUX_DESKTOP: "Linux",
}


class DesktopArtifactAdapter(ApplicationAdapter):
    """Expose native structural inspection through the common evidence model."""

    def __init__(self) -> None:
        self._last_evidence: EvidenceBundle | None = None

    @staticmethod
    def _platform(target: ApplicationTarget) -> str:
        try:
            return PLATFORMS[target.kind]
        except KeyError as exc:
            raise ValueError("DesktopArtifactAdapter requires a desktop target") from exc

    def inspect(self, target: ApplicationTarget) -> dict[str, Any]:
        self._platform(target)
        path = Path(target.locator)
        data = path.read_bytes()
        return {
            "name": path.name,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "platform": PLATFORMS[target.kind],
        }

    def generate_tests(
        self,
        target: ApplicationTarget,
        requirements: list[dict[str, Any]],
    ) -> TestPlan:
        platform = self._platform(target)
        return TestPlan(
            tests=(PlannedTest(
                test_id=f"NATIVE-{platform.upper()}-001",
                requirement_id="NATIVE-DISTRIBUTION-SAFETY",
                title=f"Attested {platform} structural and provenance inspection",
                steps=(TestStep("inspect_native_artifact", target.locator),),
            ),),
            allowed_hosts=(),
            browsers=(),
            capture_trace=False,
            capture_screenshots=False,
        )

    def execute(
        self,
        target: ApplicationTarget,
        test_plan: TestPlan,
    ) -> EvidenceBundle:
        platform = self._platform(target)
        if len(test_plan.tests) != 1 or any(
            step.action != "inspect_native_artifact"
            for step in test_plan.tests[0].steps
        ):
            raise ValueError("Desktop inspection plan is not the fixed native policy")
        scan = inspect_native_artifact(Path(target.locator), platform)
        blocking = any(
            str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
            and str(item.get("status", "FINDING")).upper() == "FINDING"
            for item in scan.findings
        )
        verified = bool(scan.metadata.get("verified_attestation"))
        if scan.status == ScannerStatus.SUCCESS and not blocking:
            status = EvidenceStatus.PASSED
        elif verified and blocking:
            status = EvidenceStatus.FAILED
        else:
            status = EvidenceStatus.INFRASTRUCTURE_FAILURE
        detail = "; ".join(scan.errors)[:2_000]
        result = NormalizedTestResult(
            test_id=test_plan.tests[0].test_id,
            requirement_id=test_plan.tests[0].requirement_id,
            status=status,
            severity="HIGH" if blocking else "INFO",
            detail=detail,
        )
        suite = ET.Element("testsuite", {
            "name": "Crucible Native", "tests": "1",
            "failures": "1" if status == EvidenceStatus.FAILED else "0",
            "errors": "1" if status == EvidenceStatus.INFRASTRUCTURE_FAILURE else "0",
        })
        case = ET.SubElement(suite, "testcase", {
            "classname": result.requirement_id, "name": result.test_id,
        })
        if status == EvidenceStatus.FAILED:
            ET.SubElement(case, "failure", {"message": "blocking native finding"})
        elif status == EvidenceStatus.INFRASTRUCTURE_FAILURE:
            ET.SubElement(case, "error", {"message": detail or "incomplete evidence"})
        self._last_evidence = EvidenceBundle(
            target=target,
            results=(result,),
            junit_xml=ET.tostring(suite, encoding="utf-8"),
            verified=verified,
            sandbox_id=str(scan.metadata.get("job_id", "")),
            isolation=dict(scan.metadata.get("isolation", {})),
            passive_findings=tuple(scan.findings),
            infrastructure_errors=tuple(scan.errors),
        )
        return self._last_evidence

    def collect_evidence(self) -> EvidenceBundle | None:
        return self._last_evidence
