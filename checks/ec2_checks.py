"""
EC2 / networking checks — cover boundary-protection controls
(e.g. NIST 800-53 SC-7, SC-28; SOC 2 CC6.6).
"""

from __future__ import annotations

import boto3

from engine.models import Status

# Ports that should never be open to 0.0.0.0/0 in a hardened environment.
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}


def check_security_groups_no_unrestricted_sensitive_ports(
    session: boto3.Session,
) -> tuple[Status, str, dict]:
    """
    NIST 800-53 SC-7 / SOC 2 CC6.6 — no security group allows unrestricted
    (0.0.0.0/0) inbound access to administrative or database ports.
    """
    client = session.client("ec2")
    paginator = client.get_paginator("describe_security_groups")

    offenders = []
    checked = 0

    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            checked += 1
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                if from_port is None or to_port is None:
                    continue

                open_ports = SENSITIVE_PORTS & set(range(from_port, to_port + 1))
                if not open_ports:
                    continue

                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        offenders.append(
                            {
                                "group_id": sg["GroupId"],
                                "group_name": sg.get("GroupName"),
                                "ports": sorted(open_ports),
                            }
                        )

    evidence = {"security_groups_checked": checked, "offending_rules": offenders}

    if offenders:
        return (
            Status.FAIL,
            f"{len(offenders)} security group rule(s) expose sensitive ports to 0.0.0.0/0.",
            evidence,
        )
    return (
        Status.PASS,
        "No security group exposes sensitive ports to unrestricted inbound access.",
        evidence,
    )


def check_ebs_default_encryption(session: boto3.Session) -> tuple[Status, str, dict]:
    """
    NIST 800-53 SC-28 / SOC 2 CC6.1 — EBS encryption-by-default is enabled
    for the account/region, so every new volume is encrypted automatically.
    """
    client = session.client("ec2")
    result = client.get_ebs_encryption_by_default()
    enabled = result.get("EbsEncryptionByDefault", False)

    evidence = {"ebs_encryption_by_default": enabled}

    if not enabled:
        return (Status.FAIL, "EBS encryption-by-default is not enabled for this region.", evidence)
    return (Status.PASS, "EBS encryption-by-default is enabled for this region.", evidence)
