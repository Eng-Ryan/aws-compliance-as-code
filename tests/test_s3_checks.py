import pytest
from checks.s3_checks import (
    check_s3_bucket_encryption,
    check_s3_public_access_blocked,
    check_s3_versioning_enabled,
)
from engine.models import Status


def test_check_s3_bucket_encryption_passes_when_all_encrypted(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="encrypted-bucket-1")
    client.put_bucket_encryption(
        Bucket="encrypted-bucket-1",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        },
    )

    status, message, evidence = check_s3_bucket_encryption(aws_session)

    assert status == Status.PASS
    assert evidence["unencrypted_buckets"] == []
    assert "encrypted-bucket-1" in evidence["buckets_checked"]


def test_check_s3_bucket_encryption_fails_when_unencrypted(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="unencrypted-bucket")

    status, message, evidence = check_s3_bucket_encryption(aws_session)

    assert status == Status.FAIL
    assert "unencrypted-bucket" in evidence["unencrypted_buckets"]
    assert "1 bucket(s) lack default encryption" in message


def test_check_s3_public_access_blocked_passes_when_all_blocked(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="secure-bucket")
    client.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    status, message, evidence = check_s3_public_access_blocked(aws_session)

    assert status == Status.PASS
    assert evidence["buckets_without_full_public_access_block"] == []


def test_check_s3_public_access_blocked_fails_when_not_blocked(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="open-bucket")

    status, message, evidence = check_s3_public_access_blocked(aws_session)

    assert status == Status.FAIL
    assert "open-bucket" in evidence["buckets_without_full_public_access_block"]


def test_check_s3_public_access_blocked_fails_when_partially_blocked(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="partial-bucket")
    client.put_public_access_block(
        Bucket="partial-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        },
    )

    status, message, evidence = check_s3_public_access_blocked(aws_session)

    assert status == Status.FAIL
    assert "partial-bucket" in evidence["buckets_without_full_public_access_block"]


def test_check_s3_versioning_enabled_passes(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="versioned-bucket")
    client.put_bucket_versioning(
        Bucket="versioned-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    status, message, evidence = check_s3_versioning_enabled(aws_session)

    assert status == Status.PASS
    assert evidence["buckets_without_versioning"] == []


def test_check_s3_versioning_enabled_fails_when_disabled(aws_session):
    client = aws_session.client("s3")
    client.create_bucket(Bucket="unversioned-bucket")

    status, message, evidence = check_s3_versioning_enabled(aws_session)

    assert status == Status.FAIL
    assert "unversioned-bucket" in evidence["buckets_without_versioning"]
