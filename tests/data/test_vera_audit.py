import csv
import gzip
from hashlib import sha256
import io
import json

from malweave.data.vera_audit import export_vera_audit


def test_disagreeing_source_is_excluded_everywhere_and_state_groups_retained(tmp_path):
    manifest = tmp_path / "manifest.csv"
    labels = tmp_path / "labels.csv"
    with manifest.open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["source_sha256", "partition", "status", "representation_sha256"]
        )
        writer.writeheader()
        for source, partition in [
            ("a", "active"),
            ("a", "latent"),
            ("b", "active"),
            ("c", "latent"),
        ]:
            writer.writerow(
                {
                    "source_sha256": source,
                    "partition": partition,
                    "status": "success",
                    "representation_sha256": "same",
                }
            )
    labels.write_text("File Hash,Classification\na,Active\nb,Active\nc,Latent\n")
    summary = export_vera_audit(manifest, labels, tmp_path / "audit")
    assert summary["unique_excluded_sources"] == 1
    assert summary["candidate_unique_sources"] == 2
    assert summary["candidate_shared_active_latent_exe_groups"] == 1
    assert not (tmp_path / "audit/split.csv").exists()


def test_timestamp_evidence_resume_and_failure_accounting(tmp_path, monkeypatch):
    from malweave.data.vera_audit import audit_vera_timestamps

    payload = gzip.compress(
        json.dumps({"lief": {"pe": {"header": {"time_date_stamp": 0}}}}).encode()
    )
    calls = []

    class S3:
        def get_object(self, **kwargs):
            calls.append(kwargs["Key"])
            return {"Body": io.BytesIO(payload)}

    monkeypatch.setattr("boto3.client", lambda *a, **kw: S3())
    manifest = tmp_path / "manifest.csv"
    with manifest.open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["source_sha256", "evidence_key", "evidence_sha256"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "source_sha256": "synthetic",
                "evidence_key": "synthetic.json.gz",
                "evidence_sha256": sha256(payload).hexdigest(),
            }
        )
    output = tmp_path / "timestamps"
    result = audit_vera_timestamps(manifest, output, "synthetic", 1)
    assert result["statuses"] == {"zero": 1}
    assert audit_vera_timestamps(manifest, output, "synthetic", 1) == result
    assert len(calls) == 1
