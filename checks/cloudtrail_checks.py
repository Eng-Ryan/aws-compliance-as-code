"""
CloudTrail checks — cover audit-logging controls
(e.g. NIST 800-53 AU-2, AU-9; SOC 2 CC7.2).
"""

from __future__ import annotations

import boto3

from engine.models import Status


def check_cloudtrail_enabled(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 AU-2 / SOC 2 CC7.2 — at least one multi-region CloudTrail
    trail exists and is actively logging.
    """
    client = session.client("cloudtrail")
    trails = client.describe_trails(includeShadowTrails=False)["trailList"]

    multi_region_active = []
    for trail in trails:
        status = client.get_trail_status(Name=trail["TrailARN"])
        if trail.get("IsMultiRegionTrail") and status.get("IsLogging"):
            multi_region_active.append(trail["Name"])

    evidence = {
        "total_trails": len(trails),
        "multi_region_active_trails": multi_region_active,
    }

    if not multi_region_active:
        return (
            Status.FAIL,
            "No actively-logging multi-region CloudTrail trail found.",
            evidence,
        )
    return (
        Status.PASS,
        f"Multi-region CloudTrail logging active: {', '.join(multi_region_active)}.",
        evidence,
    )


def check_cloudtrail_log_file_validation(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 AU-9 / SOC 2 CC7.2 — log file validation is enabled so
    tampering with CloudTrail logs after the fact can be detected.
    """
    client = session.client("cloudtrail")
    trails = client.describe_trails(includeShadowTrails=False)["trailList"]

    without_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]

    evidence = {
        "total_trails": len(trails),
        "trails_without_log_file_validation": without_validation,
    }

    if without_validation:
        return (
            Status.FAIL,
            f"{len(without_validation)} trail(s) lack log file validation: {', '.join(without_validation)}.",
            evidence,
        )
    return (Status.PASS, "Log file validation is enabled on all trails.", evidence)


def check_cloudtrail_encrypted(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 SC-28 / SOC 2 CC7.2 — CloudTrail trails should use
    KMS encryption for log files at rest.
    """
    client = session.client("cloudtrail")
    trails = client.describe_trails(includeShadowTrails=False)["trailList"]

    unencrypted = [t["Name"] for t in trails if not t.get("KmsKeyId")]

    evidence = {
        "total_trails": len(trails),
        "trails_without_kms_encryption": unencrypted,
    }

    if unencrypted:
        return (
            Status.FAIL,
            f"{len(unencrypted)} trail(s) lack KMS encryption: {', '.join(unencrypted)}.",
            evidence,
        )
    return (Status.PASS, "All trails use KMS encryption.", evidence)
