import json
from pathlib import Path
from engine.models import CheckResult, ControlDefinition, Severity, Status
from engine.report import render_html_report, write_trend_snapshot


def test_render_html_report(tmp_path):
    control = ControlDefinition(
        control_id="CC6.1-01",
        framework="soc2",
        title="Root Access Keys",
        description="Root should not have access keys",
        severity=Severity.CRITICAL,
        check_function="checks.iam_checks.check_root_access_keys",
        remediation="Delete root access keys",
        service="iam",
    )
    result = CheckResult(
        control=control,
        status=Status.PASS,
        message="Root account has no active access keys.",
        evidence={"account_access_keys_present": 0},
    )

    report_path = render_html_report([result], "test-run-001", ["soc2"], tmp_path)

    assert report_path.exists()
    content = report_path.read_text()
    assert "Compliance Report" in content
    assert "test-run-001" in content
    assert "CC6.1-01" in content
    assert "100.0%" in content


def test_write_trend_snapshot(tmp_path):
    control = ControlDefinition(
        control_id="CC6.1-01",
        framework="soc2",
        title="Root Access Keys",
        description="Root should not have access keys",
        severity=Severity.CRITICAL,
        check_function="checks.iam_checks.check_root_access_keys",
        remediation="Delete root access keys",
        service="iam",
    )
    result = CheckResult(
        control=control,
        status=Status.FAIL,
        message="Root account has active keys.",
        evidence={"account_access_keys_present": 1},
    )

    snapshot_path = write_trend_snapshot([result], "test-run-002", ["soc2"], tmp_path)

    assert snapshot_path.exists()
    with open(snapshot_path) as f:
        data = json.load(f)

    assert data["run_id"] == "test-run-002"
    assert data["frameworks"] == ["soc2"]
    assert data["total_controls"] == 1
    assert data["failed"] == 1
    assert data["compliance_score_pct"] == 0.0
