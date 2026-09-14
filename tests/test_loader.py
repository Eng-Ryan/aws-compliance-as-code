import pytest
from pathlib import Path
from engine.loader import (
    load_controls,
    load_controls_from_file,
    resolve_all,
    resolve_check_function,
)
from engine.models import ControlDefinition, Severity


def test_load_controls_from_file():
    controls_dir = Path("controls")
    soc2_path = controls_dir / "soc2_cc.yaml"

    controls = load_controls_from_file(soc2_path)

    assert len(controls) > 0
    assert all(isinstance(c, ControlDefinition) for c in controls)
    assert all(c.framework == "soc2" for c in controls)


def test_load_controls_filters_by_framework():
    controls_dir = Path("controls")

    # Load only SOC 2 controls
    soc2_controls = load_controls(controls_dir, frameworks=["soc2"])
    assert all(c.framework == "soc2" for c in soc2_controls)

    # Load only NIST controls
    nist_controls = load_controls(controls_dir, frameworks=["nist800-53"])
    assert all(c.framework == "nist800-53" for c in nist_controls)

    # Load both
    all_controls = load_controls(controls_dir, frameworks=["soc2", "nist800-53"])
    assert len(all_controls) == len(soc2_controls) + len(nist_controls)


def test_resolve_check_function():
    func = resolve_check_function("checks.iam_checks.check_root_mfa")

    assert callable(func)
    assert func.__name__ == "check_root_mfa"


def test_resolve_check_function_raises_on_invalid_path():
    with pytest.raises(ImportError):
        resolve_check_function("nonexistent.module.function")

    with pytest.raises(AttributeError):
        resolve_check_function("checks.iam_checks.nonexistent_function")


def test_resolve_all():
    controls_dir = Path("controls")
    controls = load_controls(controls_dir, frameworks=["soc2"])

    resolved = resolve_all(controls[:3])  # Test first 3 controls

    assert len(resolved) == 3
    for control, func in resolved:
        assert isinstance(control, ControlDefinition)
        assert callable(func)


def test_control_definition_from_dict():
    data = {
        "id": "TEST-001",
        "title": "Test Control",
        "description": "Test description",
        "severity": "high",
        "service": "iam",
        "check_function": "checks.iam_checks.check_root_mfa",
        "remediation": "Fix it",
    }

    control = ControlDefinition.from_dict("test-framework", data)

    assert control.control_id == "TEST-001"
    assert control.framework == "test-framework"
    assert control.severity == Severity.HIGH
    assert control.service == "iam"
