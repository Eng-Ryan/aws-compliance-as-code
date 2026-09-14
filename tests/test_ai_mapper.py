from unittest.mock import MagicMock, patch
from pathlib import Path

from engine.ai_mapper import (
    check_anthropic_available,
    draft_check_function,
    get_existing_checks_summary,
    suggest_existing_mapping,
)


def test_check_anthropic_available_returns_bool():
    result = check_anthropic_available()
    assert isinstance(result, bool)


def test_get_existing_checks_summary(tmp_path):
    # Create mock check files
    check_file = tmp_path / "mock_checks.py"
    check_file.write_text(
        'def check_something(session):\n    """NIST 800-53 AC-1 — Something."""\n    pass\n'
    )

    summary = get_existing_checks_summary(tmp_path)
    assert "def check_something(session)" in summary


@patch("engine.ai_mapper.HAS_ANTHROPIC", False)
def test_draft_check_function_graceful_when_anthropic_missing(tmp_path):
    result = draft_check_function(
        control_id="AC-17",
        framework="nist800-53",
        title="Remote Access",
        description="Authorize remote access.",
        service="ec2",
        checks_dir=tmp_path,
    )

    assert "error" in result
    assert result["review_required"] is True


@patch("engine.ai_mapper.HAS_ANTHROPIC", True)
@patch("anthropic.Anthropic")
def test_draft_check_function_calls_claude(mock_anthropic_cls, tmp_path):
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(
            text="def check_remote_access(session: boto3.Session) -> tuple[Status, str, dict]:\n    return (Status.PASS, 'ok', {})"
        )
    ]
    mock_client.messages.create.return_value = mock_response

    result = draft_check_function(
        control_id="AC-17",
        framework="nist800-53",
        title="Remote Access",
        description="Authorize remote access.",
        service="ec2",
        checks_dir=tmp_path,
    )

    assert result["function_name"] == "check_remote_access"
    assert result["suggested_file"] == "checks/ec2_checks.py"
    assert result["review_required"] is True
    assert mock_client.messages.create.called


@patch("engine.ai_mapper.HAS_ANTHROPIC", True)
@patch("anthropic.Anthropic")
def test_suggest_existing_mapping_parses_json(mock_anthropic_cls, tmp_path):
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(
            text='{"mapped_function": "checks.iam_checks.check_root_mfa", "confidence": "high", "reasoning": "Both check root MFA."}'
        )
    ]
    mock_client.messages.create.return_value = mock_response

    result = suggest_existing_mapping(
        title="Root Multi-Factor Authentication",
        description="Enforce MFA on the root account.",
        checks_dir=tmp_path,
    )

    assert result["mapped_function"] == "checks.iam_checks.check_root_mfa"
    assert result["confidence"] == "high"
    assert result["review_required"] is True
