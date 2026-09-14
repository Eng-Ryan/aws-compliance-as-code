import pytest
from checks.cloudtrail_checks import (
    check_cloudtrail_enabled,
    check_cloudtrail_encrypted,
    check_cloudtrail_log_file_validation,
)
from engine.models import Status


def test_check_cloudtrail_enabled_passes_when_multi_region_logging(aws_session):
    client = aws_session.client("cloudtrail")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="trail-bucket")

    client.create_trail(
        Name="main-trail",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=True,
    )
    client.start_logging(Name="main-trail")

    status, message, evidence = check_cloudtrail_enabled(aws_session)

    assert status == Status.PASS
    assert "main-trail" in evidence["multi_region_active_trails"]


def test_check_cloudtrail_enabled_fails_when_no_trails(aws_session):
    status, message, evidence = check_cloudtrail_enabled(aws_session)

    assert status == Status.FAIL
    assert "no actively-logging multi-region cloudtrail trail" in message.lower()
    assert evidence["multi_region_active_trails"] == []


def test_check_cloudtrail_enabled_fails_when_not_logging(aws_session):
    client = aws_session.client("cloudtrail")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="trail-bucket-2")

    client.create_trail(
        Name="inactive-trail",
        S3BucketName="trail-bucket-2",
        IsMultiRegionTrail=True,
    )
    # Don't start logging

    status, message, evidence = check_cloudtrail_enabled(aws_session)

    assert status == Status.FAIL
    assert evidence["multi_region_active_trails"] == []


def test_check_cloudtrail_log_file_validation_passes(aws_session):
    client = aws_session.client("cloudtrail")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="trail-bucket-3")

    client.create_trail(
        Name="validated-trail",
        S3BucketName="trail-bucket-3",
        EnableLogFileValidation=True,
    )

    status, message, evidence = check_cloudtrail_log_file_validation(aws_session)

    assert status == Status.PASS
    assert evidence["trails_without_log_file_validation"] == []


def test_check_cloudtrail_log_file_validation_fails(aws_session):
    client = aws_session.client("cloudtrail")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="trail-bucket-4")

    client.create_trail(
        Name="unvalidated-trail",
        S3BucketName="trail-bucket-4",
        EnableLogFileValidation=False,
    )

    status, message, evidence = check_cloudtrail_log_file_validation(aws_session)

    assert status == Status.FAIL
    assert "unvalidated-trail" in evidence["trails_without_log_file_validation"]


def test_check_cloudtrail_encrypted_passes(aws_session):
    client = aws_session.client("cloudtrail")
    kms = aws_session.client("kms")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="trail-bucket-5")

    key = kms.create_key(Description="Trail KMS Key")
    key_id = key["KeyMetadata"]["KeyId"]

    client.create_trail(
        Name="encrypted-trail",
        S3BucketName="trail-bucket-5",
        KmsKeyId=key_id,
    )

    status, message, evidence = check_cloudtrail_encrypted(aws_session)

    assert status == Status.PASS
    assert evidence["trails_without_kms_encryption"] == []


def test_check_cloudtrail_encrypted_fails_without_kms(aws_session):
    client = aws_session.client("cloudtrail")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="trail-bucket-6")

    client.create_trail(
        Name="unencrypted-trail",
        S3BucketName="trail-bucket-6",
    )

    status, message, evidence = check_cloudtrail_encrypted(aws_session)

    assert status == Status.FAIL
    assert "unencrypted-trail" in evidence["trails_without_kms_encryption"]
