"""
Loads control definitions from YAML files and resolves each control's
check_function string (e.g. "checks.iam_checks.check_root_mfa") into an
actual importable Python callable.

Keeping this resolution logic separate from the runner means new checks
can be added just by writing a function and referencing it in YAML — no
changes to the runner or engine internals required.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Callable

import yaml

from engine.models import ControlDefinition

ControlsWithChecks = list[tuple[ControlDefinition, Callable]]


def load_controls_from_file(path: Path) -> list[ControlDefinition]:
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    framework = data["framework"]
    controls = [
        ControlDefinition.from_dict(framework, entry) for entry in data["controls"]
    ]
    return controls


def load_controls(controls_dir: Path, frameworks: list[str] | None = None) -> list[ControlDefinition]:
    """
    Load all control YAML files in controls_dir. If `frameworks` is given,
    only files whose `framework` key matches one of those names are loaded
    (case-insensitive, e.g. ["soc2", "nist800-53"]).
    """
    all_controls: list[ControlDefinition] = []
    for yaml_file in sorted(controls_dir.glob("*.yaml")):
        loaded = load_controls_from_file(yaml_file)
        if frameworks:
            loaded = [c for c in loaded if c.framework.lower() in {f.lower() for f in frameworks}]
        all_controls.extend(loaded)
    return all_controls


def resolve_check_function(dotted_path: str) -> Callable:
    """
    Resolve "checks.iam_checks.check_root_mfa" into the actual function object.
    Raises ImportError / AttributeError with a clear message if the module
    or function doesn't exist, rather than failing silently at scan time.
    """
    module_path, func_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    try:
        return getattr(module, func_name)
    except AttributeError as e:
        raise AttributeError(
            f"Check function '{func_name}' not found in module '{module_path}' "
            f"(referenced by control YAML: {dotted_path})"
        ) from e


def resolve_all(controls: list[ControlDefinition]) -> ControlsWithChecks:
    resolved = []
    for control in controls:
        func = resolve_check_function(control.check_function)
        resolved.append((control, func))
    return resolved
