import csv
from hashlib import sha256
import io
import json
import struct

from malweave.data.exe_token_audit import audit_exe_tokens, token_digest
from tests.lmlm_fixtures import released_checkpoint


def test_token_audit_verifies_objects_and_resumes(tmp_path, monkeypatch):
    root = tmp_path / "checkpoint"
    released_checkpoint(root, "Unigram")
    config = json.loads((root / "config.json").read_text())
    parent = {
        "status": "completed",
        "artifact_files_sha256": {
            n: sha256((root / n).read_bytes()).hexdigest()
            for n in ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json")
        },
        "initialization": {"source_config": config, "max_tokens": 12, "max_bytes": 64},
    }
    (root / "run-manifest.json").write_text(json.dumps(parent))
    content = b"synthetic executable section"
    digest = sha256(content).hexdigest()
    calls = []

    class S3:
        def get_object(self, **kwargs):
            calls.append(kwargs["Key"])
            return {"Body": io.BytesIO(content if kwargs["Key"] == "ok" else b"mismatch")}

    monkeypatch.setattr("boto3.client", lambda *a, **kw: S3())
    path = tmp_path / "objects.csv"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["exe_sha256", "exe_bytes", "bucket", "key"])
        writer.writeheader()
        for d, key in ((digest, "ok"), ("a" * 64, "bad")):
            writer.writerow(
                {"exe_sha256": d, "exe_bytes": len(content), "bucket": "synthetic", "key": key}
            )
    output = tmp_path / "audit"
    result = audit_exe_tokens(path, root, output, 2)
    assert result["statuses"] == {"failed": 1, "success": 1}
    assert result["complete"]
    assert audit_exe_tokens(path, root, output, 2) == result
    assert len(calls) == 2
    assert token_digest([1, 2]) == sha256(struct.pack("<QII", 2, 1, 2)).hexdigest()
