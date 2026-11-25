"""Transfer receipts are exercised with synthetic data and fake HTTP responses."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import subprocess
from typing import ClassVar
from urllib.error import HTTPError, URLError

import pytest

from malweave.data import sorel_transfer as transfer
from malweave.data.sorel import SorelConfig, _verify_transfer
from malweave.data.sorel_io import SourceFailure


def test_curl_retries_and_preserves_receipts_reuses_completed_transfer(tmp_path, monkeypatch):
    calls = []

    def curl(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--output") + 1])
        output.write_bytes(b"partial" if len(calls) == 1 else b"synthetic zlib")
        return subprocess.CompletedProcess(
            command,
            22 if len(calls) == 1 else 0,
            json.dumps(
                {
                    "http_code": 503 if len(calls) == 1 else 200,
                    "size_download": output.stat().st_size,
                }
            ),
            "temporary error" if len(calls) == 1 else "",
        )

    monkeypatch.setattr(transfer.subprocess, "run", curl)
    monkeypatch.setattr(transfer.time, "sleep", lambda *args: None)
    output, receipt = transfer.download_source(tmp_path, "0" * 64, SorelConfig())
    assert len(calls) == 2
    records = [
        json.loads(path.read_text()) for path in sorted(receipt.parent.glob("attempt-*.json"))
    ]
    assert [record["http_status"] for record in records] == [503, 200]
    saved = json.loads(receipt.read_text())
    assert saved["total_received_bytes"] == len(b"partial") + len(b"synthetic zlib")
    assert saved["compressed_sha256"] == sha256(output.read_bytes()).hexdigest()
    assert transfer.download_source(tmp_path, "0" * 64, SorelConfig())[0] == output
    assert len(calls) == 2
    output.write_bytes(b"corrupt")
    with pytest.raises(SourceFailure, match="corrupt"):
        transfer.download_source(tmp_path, "0" * 64, SorelConfig())


@pytest.mark.parametrize("http", [403, 404])
def test_missing_objects_are_terminal_and_do_not_become_network_errors(
    tmp_path, monkeypatch, http
):
    calls = []

    def curl(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 22, json.dumps({"http_code": http}), "missing")

    monkeypatch.setattr(transfer.subprocess, "run", curl)
    for _ in range(2):
        with pytest.raises(SourceFailure, match=f"http_{http}"):
            transfer.download_source(tmp_path, "0" * 64, SorelConfig())
    assert len(calls) == 1
    record = json.loads(next((tmp_path / "downloads").rglob("receipt.json")).read_text())
    assert record["http_status"] == http and record["attempt"] == 1


def test_timeout_partial_data_is_accounted_and_removed(tmp_path, monkeypatch):
    def curl(command, **kwargs):
        Path(command[command.index("--output") + 1]).write_bytes(b"partial")
        raise subprocess.TimeoutExpired(
            command, 1, output=b"partial metrics", stderr=b"timeout detail"
        )

    monkeypatch.setattr(transfer.subprocess, "run", curl)
    with pytest.raises(SourceFailure, match="download_timeout"):
        transfer.download_source(tmp_path, "0" * 64, replace(SorelConfig(), request_attempts=1))
    record = json.loads(next((tmp_path / "downloads").rglob("receipt.json")).read_text())
    assert record["received_bytes"] == 7 and record["stderr"] == "timeout detail"
    assert record["http_status"] is None
    assert not list((tmp_path / "spool").iterdir())


def test_urllib_retries_and_preserves_http_metadata(tmp_path, monkeypatch):
    calls = []

    class Response(BytesIO):
        status = 200
        headers: ClassVar = {"ETag": "synthetic-etag", "Content-Length": "9"}

    def download(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise URLError("connection reset")
        return Response(b"synthetic")

    monkeypatch.setattr(transfer, "urlopen", download)
    monkeypatch.setattr(transfer.time, "sleep", lambda *args: None)
    config = replace(SorelConfig(), download_backend="urllib")
    output, receipt = transfer.download_source(tmp_path, "0" * 64, config)
    assert output.read_bytes() == b"synthetic" and len(calls) == 2
    assert json.loads(receipt.read_text())["response_headers"]["ETag"] == "synthetic-etag"
    monkeypatch.setattr(
        transfer,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            HTTPError("synthetic", 404, "missing", {}, None)
        ),
    )
    with pytest.raises(SourceFailure, match="http_404"):
        transfer.download_source(tmp_path, "1" * 64, config)


def test_oversized_transfer_stops_without_accepting_truncated_data(tmp_path, monkeypatch):
    class Response(BytesIO):
        status = 200
        headers: ClassVar = {}

    monkeypatch.setattr(transfer, "urlopen", lambda *args, **kwargs: Response(b"too long"))
    config = replace(SorelConfig(), download_backend="urllib", max_compressed_bytes=3)
    with pytest.raises(SourceFailure, match="compressed_size_limit"):
        transfer.download_source(tmp_path, "0" * 64, config)
    assert len(list((tmp_path / "downloads").rglob("attempt-*.json"))) == 1


def test_receipt_write_interruption_recovers_without_redownloading(tmp_path, monkeypatch):
    def curl(command, **kwargs):
        Path(command[command.index("--output") + 1]).write_bytes(b"synthetic")
        return subprocess.CompletedProcess(command, 0, '{"http_code":200}', "")

    monkeypatch.setattr(transfer.subprocess, "run", curl)
    _, receipt = transfer.download_source(tmp_path, "0" * 64, SorelConfig())
    receipt.unlink()  # Durable attempt and data survived; receipt checkpoint did not.
    monkeypatch.setattr(
        transfer.subprocess, "run", lambda *args, **kwargs: pytest.fail("redownload")
    )
    output, receipt = transfer.download_source(tmp_path, "0" * 64, SorelConfig())
    assert receipt.is_file() and output.read_bytes() == b"synthetic"


def test_killed_transfer_retains_interrupted_attempt_and_resumes(tmp_path, monkeypatch):
    calls = []

    def curl(command, **kwargs):
        calls.append(command)
        Path(command[command.index("--output") + 1]).write_bytes(b"partial")
        if len(calls) == 1:
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(command, 0, '{"http_code":200}', "")

    monkeypatch.setattr(transfer.subprocess, "run", curl)
    with pytest.raises(KeyboardInterrupt):
        transfer.download_source(tmp_path, "0" * 64, SorelConfig())
    assert list((tmp_path / "downloads").rglob("active.json"))
    output, receipt = transfer.download_source(tmp_path, "0" * 64, SorelConfig())
    records = [json.loads(path.read_text()) for path in sorted(receipt.parent.glob("attempt-*"))]
    assert [record["status"] for record in records] == ["download_interrupted", "success"]
    assert records[0]["received_bytes"] == 7 and not records[0]["timing_complete"]
    assert records[0]["finished_at_utc"] is None
    assert not records[1]["history_complete"]
    assert records[1]["total_received_bytes"] == 14
    assert not list((tmp_path / "spool").glob("*.part"))
    assert output.read_bytes() == b"partial"
    _verify_transfer(
        tmp_path,
        {
            "original_sha256": "0" * 64,
            "download_receipt_report_path": receipt.relative_to(tmp_path).as_posix(),
            "download_receipt_report_sha256": sha256(receipt.read_bytes()).hexdigest(),
        },
    )
