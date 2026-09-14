"""
AI-assisted control mapping.

When a new compliance control is added to the ruleset but no check_function
exists for it yet, this module can draft a candidate implementation or
suggest mapping it to an existing check — accelerating the GRC workflow
from "someone needs to write a new check" to "review and approve this
AI-drafted check."

This is deliberately narrow in scope: it drafts *one function at a time*,
in the same style as the hand-written checks in checks/, and returns it
as source code for a human to review — never auto-executes generated code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


SYSTEM_PROMPT = """You are a compliance engineering assistant. You write Python check functions
for an AWS compliance-as-code engine. Each check function:

1. Takes a single argument: session (boto3.Session)
2. Returns a tuple of (Status, str, dict) where:
   - Status is one of: Status.PASS, Status.FAIL, Status.ERROR
   - str is a human-readable message explaining the finding
   - dict is an evidence dictionary containing the raw data evaluated
3. Uses boto3 clients created from the session argument
4. Is read-only (never modifies AWS resources)
5. Handles exceptions gracefully
6. Includes a docstring referencing the relevant framework control IDs

Import Status from engine.models. Import boto3 for type hints.

Return ONLY the Python function code, no markdown fencing, no explanation outside the code."""


def check_anthropic_available() -> bool:
    """Return True if the anthropic SDK is installed and an API key is configured."""
    if not HAS_ANTHROPIC:
        return False
    try:
        client = anthropic.Anthropic()
        return bool(client.api_key)
    except Exception:
        return False


def get_existing_checks_summary(checks_dir: Path) -> str:
    """Build a summary of existing check functions for context."""
    summaries = []
    for py_file in sorted(checks_dir.glob("*.py")):
        if py_file.name == "__init__.py":
            continue
        content = py_file.read_text()
        # Extract function signatures and docstrings
        lines = content.split("\n")
        current_func = None
        for line in lines:
            if line.startswith("def check_"):
                current_func = line.strip().rstrip(":")
                summaries.append(f"\n{current_func}")
            elif current_func and line.strip().startswith('"""') and len(summaries) > 0:
                # capture first line of docstring
                doc = line.strip().strip('"""')
                if doc:
                    summaries.append(f"  # {doc}")
                current_func = None
    return "\n".join(summaries)


def draft_check_function(
    control_id: str,
    framework: str,
    title: str,
    description: str,
    service: str,
    checks_dir: Path,
    model: str = "claude-sonnet-5",
) -> dict:
    """
    Draft a candidate check function for an unmapped control.

    Returns a dict with:
        - function_name: suggested function name
        - source_code: the drafted Python source
        - suggested_file: which checks/*.py file it should go in
        - model_used: which model produced the draft
        - review_required: always True — generated code is never auto-executed
    """
    if not HAS_ANTHROPIC:
        return {
            "error": "anthropic SDK not installed. Run: pip install anthropic",
            "review_required": True,
        }

    existing = get_existing_checks_summary(checks_dir)

    prompt = f"""Draft a check function for this compliance control:

Control ID: {control_id}
Framework: {framework}
Title: {title}
Description: {description}
Primary AWS service: {service}

Here are the existing check functions in the codebase for reference on style and patterns:
{existing}

Write a single Python function following the exact same pattern. The function name should
start with "check_" and be descriptive. Include the proper imports at the top (only the
ones your function needs beyond boto3 and Status which are already imported)."""

    client = anthropic.Anthropic()
    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    source_code = message.content[0].text

    # Infer the target file from the service name
    service_file_map = {
        "iam": "iam_checks.py",
        "s3": "s3_checks.py",
        "ec2": "ec2_checks.py",
        "cloudtrail": "cloudtrail_checks.py",
        "rds": "rds_checks.py",
        "kms": "kms_checks.py",
        "lambda": "lambda_checks.py",
        "config": "config_checks.py",
    }
    suggested_file = f"checks/{service_file_map.get(service, f'{service}_checks.py')}"

    # Extract function name from the generated code
    func_name = "unknown"
    for line in source_code.split("\n"):
        if line.startswith("def check_"):
            func_name = line.split("(")[0].replace("def ", "")
            break

    return {
        "function_name": func_name,
        "source_code": source_code,
        "suggested_file": suggested_file,
        "model_used": model,
        "control_id": control_id,
        "review_required": True,
    }


def suggest_existing_mapping(
    title: str,
    description: str,
    checks_dir: Path,
    model: str = "claude-sonnet-5",
) -> dict:
    """
    Given a control description, suggest whether an existing check function
    already covers it (possibly under a different framework's control ID).

    Returns a dict with:
        - mapped_function: dotted path if a match was found, None otherwise
        - confidence: "high", "medium", or "low"
        - reasoning: why the model thinks this mapping is correct
        - review_required: always True
    """
    if not HAS_ANTHROPIC:
        return {
            "error": "anthropic SDK not installed. Run: pip install anthropic",
            "review_required": True,
        }

    existing = get_existing_checks_summary(checks_dir)

    prompt = f"""Given this compliance control:
Title: {title}
Description: {description}

And these existing check functions:
{existing}

Does an existing check function already evaluate what this control requires?

Respond in JSON with:
- "mapped_function": the function name if there's a match, or null
- "confidence": "high", "medium", or "low"
- "reasoning": one sentence explaining your assessment"""

    client = anthropic.Anthropic()
    message = client.messages.create(
        model=model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )

    try:
        result = json.loads(message.content[0].text)
    except json.JSONDecodeError:
        result = {
            "mapped_function": None,
            "confidence": "low",
            "reasoning": message.content[0].text,
        }

    result["model_used"] = model
    result["review_required"] = True
    return result
