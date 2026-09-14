import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def aws_session():
    """
    A boto3 Session backed entirely by moto's mocked AWS backend.
    No real credentials or network calls are used.
    """
    with mock_aws():
        yield boto3.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name="us-east-1",
        )
