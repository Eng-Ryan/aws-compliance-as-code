import json
from pathlib import Path
from engine.evidence import EvidenceCollector
from engine.models import CheckResult, ControlDefinition, Severity, Status


def test_evidence_collector_capture(tmp_path):
    collector = EvidenceCollector(output_dir=tmp_path)

    control = ControlDefinition(
        control_id="TEST-001",
        framework="soc2",
        title="Test Control",
        description="A test control",
        severity=Severity.HIGH,
        check_function="test.func",
        remediation="Fix it",
        service="iam",
    )

    result = CheckResult(
        control=control,
        status=Status.PASS,
        message="All good",
        evidence={"buckets": ["bucket-a", "bucket-b"]},
    )

    entry = collector.capture(result, "run-123")

    assert entry["control_id"] == "TEST-001"
    assert "sha256" in entry
    assert len(entry["sha256"]) == 64  # SHA-256 hex digest length
    assert Path(entry["location"]).exists()

    # Read back the saved file and verify content
    with open(entry["location"]) as f:
        data = json.load(f)

    assert data["control_id"] == "TEST-001"
    assert data["status"] == "pass"
    assert data["sha256"] == entry["sha256"]
    assert data["evidence"] == {"buckets": ["bucket-a", "bucket-b"]}


def test_evidence_collector_capture_all(tmp_path):
    collector = EvidenceCollector(output_dir=tmp_path)

    control = ControlDefinition(
        control_id="TEST-002",
        framework="soc2",
        title="Test Control 2",
        description="A test control 2",
        severity=Severity.CRITICAL,
        check_function="test.func",
        remediation="Fix it",
        service="s3",
    )

    result = CheckResult(
        control=control,
        status=Status.FAIL,
        message="Bucket unencrypted",
        evidence={"unencrypted": ["bad-bucket"]},
    )

    manifest_path = collector.capture_all([result], "run-456")

    assert manifest_path.exists()

    with open(manifest_path) as f:
        manifest = json.load(f)

    assert manifest["run_id"] == "run-456"
    assert manifest["entry_count"] == 1
    assert len(manifest["entries"]) == 1
    assert manifest["entries"][0]["control_id"] == "TEST-002"
