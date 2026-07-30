"""Desktop targets normalize attested scanner results into common evidence."""

from adapters.desktop import DesktopArtifactAdapter
from application_adapters import ApplicationTarget, EvidenceStatus, TargetKind
from scan_models import ScannerResult, ScannerStatus


def test_desktop_adapter_generates_fixed_non_executing_plan(tmp_path):
    artifact = tmp_path / "Demo.exe"
    artifact.write_bytes(b"MZ")
    target = ApplicationTarget(TargetKind.WINDOWS_DESKTOP, str(artifact))
    adapter = DesktopArtifactAdapter()

    plan = adapter.generate_tests(target, [])

    assert len(plan.tests) == 1
    assert plan.tests[0].steps[0].action == "inspect_native_artifact"
    assert plan.tests[0].destructive is False


def test_desktop_adapter_normalizes_verified_evidence(monkeypatch, tmp_path):
    artifact = tmp_path / "Demo.deb"
    artifact.write_bytes(b"!<arch>\n")
    target = ApplicationTarget(TargetKind.LINUX_DESKTOP, str(artifact))
    adapter = DesktopArtifactAdapter()
    monkeypatch.setattr(
        "adapters.desktop.inspect_native_artifact",
        lambda *_: ScannerResult(
            "desktop_artifact", ScannerStatus.SUCCESS,
            metadata={
                "verified_attestation": True,
                "job_id": "job-1",
                "isolation": {"ephemeral": True},
            },
        ),
    )

    evidence = adapter.execute(target, adapter.generate_tests(target, []))

    assert evidence.verified is True
    assert evidence.sandbox_id == "job-1"
    assert evidence.results[0].status == EvidenceStatus.PASSED
    assert evidence.pass_rate == 1.0


def test_desktop_adapter_does_not_pass_partial_worker_evidence(monkeypatch, tmp_path):
    artifact = tmp_path / "Demo.pkg"
    artifact.write_bytes(b"xar!")
    target = ApplicationTarget(TargetKind.MAC_DESKTOP, str(artifact))
    adapter = DesktopArtifactAdapter()
    monkeypatch.setattr(
        "adapters.desktop.inspect_native_artifact",
        lambda *_: ScannerResult(
            "desktop_artifact", ScannerStatus.PARTIAL,
            errors=["notarization unavailable"],
            metadata={"verified_attestation": True, "job_id": "job-2"},
        ),
    )

    evidence = adapter.execute(target, adapter.generate_tests(target, []))

    assert evidence.verified is True
    assert evidence.results[0].status == EvidenceStatus.INFRASTRUCTURE_FAILURE
    assert evidence.pass_rate is None
