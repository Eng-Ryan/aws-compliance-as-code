import pytest
from checks.ec2_checks import (
    check_ebs_default_encryption,
    check_security_groups_no_unrestricted_sensitive_ports,
)
from engine.models import Status


def test_check_security_groups_passes_with_no_violations(aws_session):
    client = aws_session.client("ec2")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    # Security group with restricted SSH access (not 0.0.0.0/0)
    client.create_security_group(
        GroupName="restricted-sg",
        Description="Restricted access",
        VpcId=vpc_id,
    )

    status, message, evidence = check_security_groups_no_unrestricted_sensitive_ports(aws_session)

    assert status == Status.PASS
    assert evidence["offending_rules"] == []


def test_check_security_groups_fails_with_unrestricted_ssh(aws_session):
    client = aws_session.client("ec2")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = client.create_security_group(
        GroupName="open-ssh-sg",
        Description="Open SSH",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    status, message, evidence = check_security_groups_no_unrestricted_sensitive_ports(aws_session)

    assert status == Status.FAIL
    assert len(evidence["offending_rules"]) > 0
    assert any(22 in rule["ports"] for rule in evidence["offending_rules"])


def test_check_security_groups_fails_with_unrestricted_database_ports(aws_session):
    client = aws_session.client("ec2")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = client.create_security_group(
        GroupName="open-db-sg",
        Description="Open database",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    status, message, evidence = check_security_groups_no_unrestricted_sensitive_ports(aws_session)

    assert status == Status.FAIL
    assert any(3306 in rule["ports"] for rule in evidence["offending_rules"])


def test_check_ebs_default_encryption_passes(aws_session):
    client = aws_session.client("ec2")
    client.enable_ebs_encryption_by_default()

    status, message, evidence = check_ebs_default_encryption(aws_session)

    assert status == Status.PASS
    assert evidence["ebs_encryption_by_default"] is True


def test_check_ebs_default_encryption_fails(aws_session):
    status, message, evidence = check_ebs_default_encryption(aws_session)

    assert status == Status.FAIL
    assert evidence["ebs_encryption_by_default"] is False
    assert "not enabled" in message.lower()
