import csv
from hashlib import sha256
from io import BytesIO
import sqlite3

from malweave.data import rawmal_die


def test_pilot_and_resume_export(tmp_path, monkeypatch):
    inputs = [b"synthetic-a", b"synthetic-b"]
    keys = {f"raw/{h[:2]}/{h}": data for data in inputs if (h := sha256(data).hexdigest())}
    manifest = tmp_path / "input.csv"
    with manifest.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            ["sha256", "s3_key", "bytes", "format", "pe_machine", "type_labels", "family_labels"]
        )
        for key, data in keys.items():
            writer.writerow([key.split("/")[-1], key, len(data), "pe", "0x014c", "[]", "[]"])

    class Client:
        def get_object(self, *, Bucket, Key):
            assert Bucket == "private-test"
            return {"Body": BytesIO(keys[Key]), "ETag": '"test-etag"'}

    executable = tmp_path / "diec"
    executable.write_text("#!/bin/sh\nprintf 'die 3.21\\n'\n")
    executable.chmod(0o700)
    (tmp_path / "db").mkdir()
    monkeypatch.setattr(rawmal_die.boto3, "client", lambda *a, **kw: Client())
    monkeypatch.setattr(rawmal_die, "assess_file", lambda *a: {"status": "success"})

    retry = False

    def packing(_tool, path, _timeout):
        valid = retry or path.read_bytes() == inputs[0]
        return {
            "state": "not_detected" if valid else "unknown",
            "types": [],
            "modes": {
                "recursive": "success",
                "deep": "success",
                "heuristic": "success" if valid else "timeout",
            },
        }

    monkeypatch.setattr(rawmal_die, "assess_packing", packing)
    job = tmp_path / "job"
    for pending in (1, 0):
        result = rawmal_die.run_rawmal_die(
            job,
            bucket="private-test",
            manifest_path=manifest,
            die_command=str(executable),
            workers=64,
            limit=1,
        )
        assert result["pending"] == pending
        assert not list((job / "work").iterdir())
    assert result["csv"] == {"assessment_rows": 2, "filtered_rows": 1}

    retry = True
    for expected in (1, 0):
        result = rawmal_die.run_rawmal_die(
            job,
            bucket="private-test",
            manifest_path=manifest,
            die_command=str(executable),
            limit=1,
            retry_unknown=True,
        )
        assert result["retry_done"] == expected
        assert result["csv"] == {"assessment_rows": 2, "filtered_rows": 2}
    with sqlite3.connect(job / "state.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM retry_history").fetchone() == (1,)
