"""Web application adapter combining static inspection and remote browser evidence."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

try:
    from ..application_adapters import (
        ApplicationAdapter,
        ApplicationTarget,
        EvidenceBundle,
        PlannedTest,
        TargetKind,
        TestPlan,
        TestStep,
    )
    from ..browser_sandbox import execute_browser_plan
    from ..upload_scanner import scan_web_url
except ImportError:
    from application_adapters import (
        ApplicationAdapter,
        ApplicationTarget,
        EvidenceBundle,
        PlannedTest,
        TargetKind,
        TestPlan,
        TestStep,
    )
    from browser_sandbox import execute_browser_plan
    from upload_scanner import scan_web_url


class WebAppAdapter(ApplicationAdapter):
    def __init__(self) -> None:
        self._last_evidence: EvidenceBundle | None = None

    def inspect(self, target: ApplicationTarget) -> Any:
        if target.kind != TargetKind.WEB:
            raise ValueError("WebAppAdapter requires a WEB target")
        return scan_web_url(target.locator)

    def generate_tests(
        self,
        target: ApplicationTarget,
        requirements: list[dict[str, Any]],
    ) -> TestPlan:
        hostname = (urlsplit(target.locator).hostname or "").lower().rstrip(".")
        tests: list[PlannedTest] = [
            PlannedTest(
                test_id="WEB-PASSIVE-001",
                requirement_id="WEB-BASELINE",
                title="Entry page loads without browser or network errors",
                steps=(TestStep("navigate", target.locator), TestStep("assert_page_loaded")),
            ),
            PlannedTest(
                test_id="WEB-DISCOVERY-001",
                requirement_id="WEB-ATTACK-SURFACE",
                title="Same-host links load and forms are inventoried",
                steps=(
                    TestStep("navigate", target.locator),
                    TestStep("discover_surface"),
                ),
            ),
            PlannedTest(
                test_id="WEB-A11Y-001",
                requirement_id="WEB-ACCESSIBILITY",
                title="Entry page has no serious or critical axe violations",
                steps=(TestStep("navigate", target.locator), TestStep("run_axe")),
            ),
            PlannedTest(
                test_id="WEB-HEADERS-001",
                requirement_id="WEB-PASSIVE-SECURITY",
                title="Entry response and cookies meet passive security policy",
                steps=(TestStep("navigate", target.locator), TestStep("inspect_response")),
            ),
        ]
        for index, requirement in enumerate(requirements[:16], start=1):
            requirement_id = str(
                requirement.get("req_id") or requirement.get("id") or f"REQ-{index}"
            )
            title = str(requirement.get("description") or requirement.get("title") or "")
            if not title:
                continue
            tests.append(
                PlannedTest(
                    test_id=f"WEB-REQ-{index:03d}",
                    requirement_id=requirement_id,
                    title=title[:300],
                    steps=(
                        TestStep(
                            "review_required",
                            value=(
                                "Requirement needs a typed journey mapped to the "
                                "hashed application model; no selector was invented."
                            ),
                        ),
                    ),
                )
            )
        return TestPlan(
            tests=tuple(tests),
            allowed_hosts=(hostname,),
            browsers=("chromium", "firefox", "webkit"),
            capture_trace=True,
            capture_screenshots=True,
            capture_video=False,
        )

    def execute(
        self,
        target: ApplicationTarget,
        test_plan: TestPlan,
    ) -> EvidenceBundle:
        self._last_evidence = execute_browser_plan(target, test_plan)
        return self._last_evidence

    def collect_evidence(self) -> EvidenceBundle | None:
        return self._last_evidence
