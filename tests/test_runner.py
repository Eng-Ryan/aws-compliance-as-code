from engine.models import CheckResult, ControlDefinition, Severity, Status
from engine.runner import ComplianceRunner


def dummy_pass_check(session):
    return (Status.PASS, "Passed check", {"status": "ok"})


def dummy_fail_check(session):
    return (Status.FAIL, "Failed check", {"status": "failed"})


def dummy_error_check(session):
    raise ValueError("Something exploded")


def test_runner_executes_checks(aws_session):
    control1 = ControlDefinition(
        control_id="C1",
        framework="soc2",
        title="Control 1",
        description="Desc",
        severity=Severity.HIGH,
        check_function="dummy",
        remediation="Rem",
        service="iam",
    )
    control2 = ControlDefinition(
        control_id="C2",
        framework="soc2",
        title="Control 2",
        description="Desc",
        severity=Severity.LOW,
        check_function="dummy",
        remediation="Rem",
        service="s3",
    )

    runner = ComplianceRunner(session=aws_session, max_workers=2)
    results = runner.run([
        (control1, dummy_pass_check),
        (control2, dummy_fail_check),
    ])

    assert len(results) == 2
    assert results[0].status == Status.PASS
    assert results[1].status == Status.FAIL


def test_runner_handles_exceptions_gracefully(aws_session):
    control = ControlDefinition(
        control_id="C-ERR",
        framework="soc2",
        title="Error Control",
        description="Desc",
        severity=Severity.MEDIUM,
        check_function="dummy",
        remediation="Rem",
        service="ec2",
    )

    runner = ComplianceRunner(session=aws_session)
    results = runner.run([(control, dummy_error_check)])

    assert len(results) == 1
    assert results[0].status == Status.ERROR
    assert "Something exploded" in results[0].message
    assert results[0].error is not None


def test_runner_summarize():
    control = ControlDefinition(
        control_id="C",
        framework="soc2",
        title="T",
        description="D",
        severity=Severity.HIGH,
        check_function="cf",
        remediation="R",
        service="iam",
    )

    results = [
        CheckResult(control=control, status=Status.PASS, message="pass"),
        CheckResult(control=control, status=Status.PASS, message="pass"),
        CheckResult(control=control, status=Status.FAIL, message="fail"),
        CheckResult(control=control, status=Status.ERROR, message="error"),
        CheckResult(control=control, status=Status.NOT_APPLICABLE, message="n/a"),
    ]

    summary = ComplianceRunner.summarize(results)

    assert summary["total_controls"] == 5
    assert summary["passed"] == 2
    assert summary["failed"] == 1
    assert summary["errored"] == 1
    assert summary["not_applicable"] == 1
    # Scored = 4 (total - na), passed = 2, so score = 50.0%
    assert summary["compliance_score_pct"] == 50.0
