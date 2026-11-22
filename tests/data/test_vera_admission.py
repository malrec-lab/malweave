import csv
from hashlib import sha256
import io
from types import SimpleNamespace

from malweave.data.vera_admission import run_admission


def test_static_admission_digest_evidence_and_resume(tmp_path, monkeypatch):
    import malweave.data.vera_admission as module

    payload = b"synthetic PE data only"
    source = sha256(payload).hexdigest()
    manifest = tmp_path / "inventory.csv"
    row = {
        "source_sha256": source,
        "source_bytes": len(payload),
        "source_etag": '"synthetic"',
        "source_key": "vera/zenodo-17904705-v1/binaries/synthetic",
        "csv_classification": "Active",
        "representation_sha256": "synthetic-exe",
        "eligibility_status": "candidate",
    }
    with manifest.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    die = tmp_path / "tool" / "app" / "Contents" / "MacOS" / "diec"
    die.parent.mkdir(parents=True)
    die.write_bytes(b"synthetic tool identity")
    calls = []

    class Body(io.BytesIO):
        def iter_chunks(self, size):
            while block := self.read(size):
                yield block

    class S3:
        def get_object(self, **kwargs):
            calls.append(kwargs)
            return {"Body": Body(payload)}

    monkeypatch.setattr(module.boto3, "client", lambda *a, **kw: S3())
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="synthetic version", stderr=""),
    )
    monkeypatch.setattr(
        module,
        "assess_file",
        lambda *a: {"status": "success", "stdout": "Intel 80386", "command": ["synthetic"]},
    )
    monkeypatch.setattr(
        module,
        "assess_packing",
        lambda *a: {"state": "not_detected", "reports": {"synthetic": "complete"}},
    )
    output = tmp_path / "out"
    result = run_admission(manifest, output, "synthetic", die, 2)
    assert result["complete"]
    assert result["statuses"] == {"success": 1}
    assert len(list((output / "records").glob("*.json.gz"))) == 1
    assert run_admission(manifest, output, "synthetic", die, 2)["completed"] == 1
    assert len(calls) == 1
