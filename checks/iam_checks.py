"""
IAM checks — cover the identity/access-control family of controls
(e.g. NIST 800-53 AC-2, IA-2, IA-5; SOC 2 CC6.1).

Every check has the signature:
    def check_xyz(session: boto3.Session) -> tuple[Status, str, dict]

and returns (status, human_readable_message, evidence_dict). The evidence
dict is what gets hashed and persisted by engine.evidence — it should
contain enough raw detail to be defensible to an auditor, not just the
pass/fail conclusion.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import boto3
import botocore

from engine.models import Status


def check_iam_password_policy(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 IA-5 / SOC 2 CC6.1 — account password policy meets a
    reasonable minimum bar (length, complexity, reuse prevention, expiry).
    """
    client = session.client("iam")
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        return (
            Status.FAIL,
            "No IAM account password policy is configured.",
            {"password_policy": None},
        )

    failures = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        failures.append("minimum length below 14 characters")
    if not policy.get("RequireSymbols"):
        failures.append("symbols not required")
    if not policy.get("RequireNumbers"):
        failures.append("numbers not required")
    if not policy.get("RequireUppercaseCharacters"):
        failures.append("uppercase not required")
    if not policy.get("RequireLowercaseCharacters"):
        failures.append("lowercase not required")
    if policy.get("PasswordReusePrevention", 0) < 24:
        failures.append("password reuse prevention below 24")
    if not policy.get("MaxPasswordAge"):
        failures.append("no maximum password age set")

    evidence = {"password_policy": policy}

    if failures:
        return (
            Status.FAIL,
            f"Password policy does not meet baseline: {', '.join(failures)}.",
            evidence,
        )
    return (Status.PASS, "Password policy meets baseline requirements.", evidence)


def check_root_access_keys(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 AC-6 / SOC 2 CC6.1 — the root account must not have
    active access keys. Root should only ever be used via the console
    with MFA, never programmatically.
    """
    client = session.client("iam")
    summary = client.get_account_summary()["SummaryMap"]
    active_keys = summary.get("AccountAccessKeysPresent", 0)

    evidence = {"account_access_keys_present": active_keys}

    if active_keys:
        return (
            Status.FAIL,
            "Root account has active access keys. These should be deleted.",
            evidence,
        )
    return (Status.PASS, "Root account has no active access keys.", evidence)


def check_root_mfa(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 IA-2(1) / SOC 2 CC6.1 — the root account must have MFA
    enabled, since root bypasses all IAM policy restrictions.
    """
    client = session.client("iam")
    summary = client.get_account_summary()["SummaryMap"]
    mfa_enabled = summary.get("AccountMFAEnabled", 0)

    evidence = {"account_mfa_enabled": mfa_enabled}

    if not mfa_enabled:
        return (Status.FAIL, "Root account does not have MFA enabled.", evidence)
    return (Status.PASS, "Root account has MFA enabled.", evidence)


def check_iam_users_mfa(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 IA-2(1) / SOC 2 CC6.1 — every IAM user with console
    access should have MFA enabled.
    """
    client = session.client("iam")
    paginator = client.get_paginator("list_users")

    users_without_mfa = []
    total_users = 0

    for page in paginator.paginate():
        for user in page["Users"]:
            total_users += 1
            username = user["UserName"]

            # Skip users with no console login profile (programmatic-only users)
            try:
                client.get_login_profile(UserName=username)
            except client.exceptions.NoSuchEntityException:
                continue

            mfa_devices = client.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                users_without_mfa.append(username)

    evidence = {
        "total_iam_users": total_users,
        "users_without_mfa": users_without_mfa,
    }

    if users_without_mfa:
        return (
            Status.FAIL,
            f"{len(users_without_mfa)} console-enabled IAM user(s) lack MFA: "
            f"{', '.join(users_without_mfa)}.",
            evidence,
        )
    return (Status.PASS, "All console-enabled IAM users have MFA enabled.", evidence)


def check_iam_unused_credentials(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 AC-2 / SOC 2 CC6.1 — IAM credentials (access keys) not used
    in the last 90 days should be disabled. Stale credentials are a common
    vector for unauthorized access.
    """
    client = session.client("iam")
    paginator = client.get_paginator("list_users")

    stale = []
    checked = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    for page in paginator.paginate():
        for user in page["Users"]:
            checked += 1
            username = user["UserName"]
            keys = client.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] == "Active":
                    last_used_resp = client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    last_used = last_used_resp["AccessKeyLastUsed"].get("LastUsedDate")
                    if last_used is None or last_used < cutoff:
                        stale.append({
                            "username": username,
                            "access_key_id": key["AccessKeyId"],
                            "last_used": last_used.isoformat() if last_used else "never",
                        })

    evidence = {"users_checked": checked, "stale_credentials": stale}

    if stale:
        return (
            Status.FAIL,
            f"{len(stale)} access key(s) unused for 90+ days.",
            evidence,
        )
    return (Status.PASS, "No stale IAM access keys found.", evidence)
