from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from checks.iam_checks import (
    check_iam_password_policy,
    check_iam_unused_credentials,
    check_iam_users_mfa,
    check_root_access_keys,
    check_root_mfa,
)
from engine.models import Status


def test_check_iam_password_policy_fails_when_no_policy_set(aws_session):
    status, message, evidence = check_iam_password_policy(aws_session)

    assert status == Status.FAIL
    assert "no iam account password policy" in message.lower()
    assert evidence["password_policy"] is None


def test_check_iam_password_policy_passes_when_baseline_met(aws_session):
    client = aws_session.client("iam")
    client.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        PasswordReusePrevention=24,
        MaxPasswordAge=90,
    )

    status, message, evidence = check_iam_password_policy(aws_session)

    assert status == Status.PASS
    assert evidence["password_policy"]["MinimumPasswordLength"] == 14


def test_check_iam_password_policy_fails_when_weak(aws_session):
    client = aws_session.client("iam")
    client.update_account_password_policy(
        MinimumPasswordLength=6,
        RequireSymbols=False,
    )

    status, message, evidence = check_iam_password_policy(aws_session)

    assert status == Status.FAIL
    assert "minimum length" in message.lower()


def test_check_iam_users_mfa_passes_with_no_console_users(aws_session):
    client = aws_session.client("iam")
    # Programmatic-only user — no login profile, so it should not count against MFA.
    client.create_user(UserName="ci-deploy-bot")

    status, message, evidence = check_iam_users_mfa(aws_session)

    assert status == Status.PASS
    assert evidence["total_iam_users"] == 1
    assert evidence["users_without_mfa"] == []


def test_check_iam_users_mfa_fails_for_console_user_without_mfa(aws_session):
    client = aws_session.client("iam")
    client.create_user(UserName="alice")
    client.create_login_profile(UserName="alice", Password="TempPassw0rd!23")

    status, message, evidence = check_iam_users_mfa(aws_session)

    assert status == Status.FAIL
    assert "alice" in evidence["users_without_mfa"]


def test_check_root_access_keys_passes_when_no_keys(aws_session):
    status, message, evidence = check_root_access_keys(aws_session)

    assert status == Status.PASS
    assert "no active access keys" in message.lower()
    assert evidence["account_access_keys_present"] == 0


def test_check_root_access_keys_fails_when_keys_present(aws_session):
    # Mock get_account_summary to return AccountAccessKeysPresent = 1
    client = aws_session.client("iam")
    with patch.object(
        client,
        "get_account_summary",
        return_value={"SummaryMap": {"AccountAccessKeysPresent": 1}},
    ):
        status, message, evidence = check_root_access_keys(aws_session)

    assert status == Status.FAIL
    assert "active access keys" in message.lower()
    assert evidence["account_access_keys_present"] == 1


def test_check_root_mfa_passes_when_enabled(aws_session):
    client = aws_session.client("iam")
    with patch.object(
        client,
        "get_account_summary",
        return_value={"SummaryMap": {"AccountMFAEnabled": 1}},
    ):
        status, message, evidence = check_root_mfa(aws_session)

    assert status == Status.PASS
    assert "mfa enabled" in message.lower()
    assert evidence["account_mfa_enabled"] == 1


def test_check_root_mfa_fails_when_disabled(aws_session):
    status, message, evidence = check_root_mfa(aws_session)

    assert status == Status.FAIL
    assert "does not have mfa enabled" in message.lower()
    assert evidence["account_mfa_enabled"] == 0


def test_check_iam_unused_credentials_passes_with_no_stale_keys(aws_session):
    client = aws_session.client("iam")
    client.create_user(UserName="active-user")
    key_resp = client.create_access_key(UserName="active-user")
    key_id = key_resp["AccessKey"]["AccessKeyId"]

    # Mock get_access_key_last_used to return a recent date (10 days ago)
    recent_date = datetime.now(timezone.utc) - timedelta(days=10)
    with patch.object(
        client,
        "get_access_key_last_used",
        return_value={"AccessKeyLastUsed": {"LastUsedDate": recent_date}},
    ):
        status, message, evidence = check_iam_unused_credentials(aws_session)

    assert status == Status.PASS
    assert evidence["stale_credentials"] == []


def test_check_iam_unused_credentials_fails_with_stale_key(aws_session):
    client = aws_session.client("iam")
    client.create_user(UserName="inactive-user")
    client.create_access_key(UserName="inactive-user")

    # Mock get_access_key_last_used to return an old date (120 days ago)
    old_date = datetime.now(timezone.utc) - timedelta(days=120)
    with patch.object(
        client,
        "get_access_key_last_used",
        return_value={"AccessKeyLastUsed": {"LastUsedDate": old_date}},
    ):
        status, message, evidence = check_iam_unused_credentials(aws_session)

    assert status == Status.FAIL
    assert len(evidence["stale_credentials"]) == 1
    assert evidence["stale_credentials"][0]["username"] == "inactive-user"


def test_check_iam_unused_credentials_fails_with_never_used_key(aws_session):
    client = aws_session.client("iam")
    client.create_user(UserName="never-used-user")
    client.create_access_key(UserName="never-used-user")

    # get_access_key_last_used returns empty AccessKeyLastUsed dict (never used)
    with patch.object(
        client,
        "get_access_key_last_used",
        return_value={"AccessKeyLastUsed": {}},
    ):
        status, message, evidence = check_iam_unused_credentials(aws_session)

    assert status == Status.FAIL
    assert len(evidence["stale_credentials"]) == 1
    assert evidence["stale_credentials"][0]["last_used"] == "never"
