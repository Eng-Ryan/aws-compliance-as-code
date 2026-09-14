"""
S3 checks — cover data protection controls
(e.g. NIST 800-53 SC-13, SC-28; SOC 2 CC6.1, CC6.7).
"""

from __future__ import annotations

import boto3
import botocore

from engine.models import Status


def check_s3_bucket_encryption(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 SC-28 / SOC 2 CC6.1 — every S3 bucket has default
    server-side encryption enabled.
    """
    client = session.client("s3")
    buckets = client.list_buckets()["Buckets"]

    unencrypted = []
    checked = []

    for bucket in buckets:
        name = bucket["Name"]
        checked.append(name)
        try:
            client.get_bucket_encryption(Bucket=name)
        except client.exceptions.ClientError as e:  # type: ignore[attr-defined]
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                unencrypted.append(name)
            else:
                raise

    evidence = {"buckets_checked": checked, "unencrypted_buckets": unencrypted}

    if unencrypted:
        return (
            Status.FAIL,
            f"{len(unencrypted)} bucket(s) lack default encryption: {', '.join(unencrypted)}.",
            evidence,
        )
    return (Status.PASS, "All S3 buckets have default encryption enabled.", evidence)


def check_s3_public_access_blocked(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 AC-3 / SOC 2 CC6.1 — every S3 bucket blocks public access
    at the bucket level (the account-level block is not sufficient on its
    own, since it can be overridden per-bucket by a permissive user).
    """
    client = session.client("s3")
    buckets = client.list_buckets()["Buckets"]

    not_blocked = []
    checked = []

    for bucket in buckets:
        name = bucket["Name"]
        checked.append(name)
        try:
            config = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(
                config.get(key, False)
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
            if not fully_blocked:
                not_blocked.append(name)
        except client.exceptions.ClientError as e:  # type: ignore[attr-defined]
            code = e.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                not_blocked.append(name)
            else:
                raise

    evidence = {"buckets_checked": checked, "buckets_without_full_public_access_block": not_blocked}

    if not_blocked:
        return (
            Status.FAIL,
            f"{len(not_blocked)} bucket(s) do not fully block public access: {', '.join(not_blocked)}.",
            evidence,
        )
    return (Status.PASS, "All S3 buckets fully block public access.", evidence)


def check_s3_versioning_enabled(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 CP-9 / SOC 2 CC6.1 — versioning enabled to protect against
    accidental or malicious object deletion/overwrite.
    """
    client = session.client("s3")
    buckets = client.list_buckets()["Buckets"]

    not_versioned = []
    checked = []

    for bucket in buckets:
        name = bucket["Name"]
        checked.append(name)
        status = client.get_bucket_versioning(Bucket=name).get("Status")
        if status != "Enabled":
            not_versioned.append(name)

    evidence = {"buckets_checked": checked, "buckets_without_versioning": not_versioned}

    if not_versioned:
        return (
            Status.FAIL,
            f"{len(not_versioned)} bucket(s) do not have versioning enabled: {', '.join(not_versioned)}.",
            evidence,
        )
    return (Status.PASS, "All S3 buckets have versioning enabled.", evidence)
