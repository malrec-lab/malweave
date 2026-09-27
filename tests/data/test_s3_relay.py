"""Credential isolation and endpoint validation without network access."""

import boto3
import pytest

from malweave.data.s3.relay import RelayError, make_runpod_client


def test_runpod_client_never_uses_source_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-source-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-source-secret")
    for key, value in {
        "ENDPOINT_URL": "https://s3api-test.runpod.io",
        "REGION": "test",
        "ACCESS_KEY_ID": "synthetic-destination-access",
        "SECRET_ACCESS_KEY": "synthetic-destination-secret",
    }.items():
        monkeypatch.setenv("RUNPOD_S3_" + key, value)
    captured = {}
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: captured.update(kwargs))
    make_runpod_client(4)
    assert captured["aws_access_key_id"] == "synthetic-destination-access"
    assert captured["aws_secret_access_key"] == "synthetic-destination-secret"
    assert captured["endpoint_url"] == "https://s3api-test.runpod.io"
    monkeypatch.delenv("RUNPOD_S3_SECRET_ACCESS_KEY")
    with pytest.raises(RelayError, match="Missing"):
        make_runpod_client()


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://s3api-test.runpod.io",
        "https://example.org",
        "https://user:password@s3api-test.runpod.io",
    ],
)
def test_unsafe_endpoint_rejected_before_sdk_creation(monkeypatch, endpoint):
    for key in ("REGION", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY"):
        monkeypatch.setenv("RUNPOD_S3_" + key, "synthetic")
    with pytest.raises(RelayError, match="HTTPS Runpod"):
        make_runpod_client(endpoint_url=endpoint)
