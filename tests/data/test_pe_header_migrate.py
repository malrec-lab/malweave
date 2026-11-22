import csv
from hashlib import sha256
import io

from botocore.exceptions import ClientError
import pytest

from malweave.data.pe_header_migrate import migrate_headers


@pytest.mark.parametrize("corrupt", [False, True])
def test_migration_verifies_preserves_failures_and_resumes(tmp_path, monkeypatch, corrupt):
    payload = b"synthetic header"
    source = "a" * 64
    old = "rands/representations/pe-header/runs/test/sources/" + source + "/header.bin"
    new = "rands/representations/pe-header/aa/" + source + ".bin"
    objects = {old: payload}
    if corrupt:
        objects[new] = b"wrong"
    copies = []

    class Client:
        def get_object(self, Bucket, Key):
            if Key not in objects:
                raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
            return {"Body": io.BytesIO(objects[Key])}

        def copy_object(self, Bucket, Key, CopySource, **kwargs):
            copies.append(Key)
            objects[Key] = objects[CopySource["Key"]]

        def put_object(self, Bucket, Key, Body, **kwargs):
            objects[Key] = Body

    monkeypatch.setattr("malweave.data.pe_header_migrate.boto3.client", lambda *a, **k: Client())
    manifest = tmp_path / "input.csv"
    rows = [
        {
            "source_sha256": source,
            "status": "success",
            "header_sha256": sha256(payload).hexdigest(),
            "size_of_headers": len(payload),
            "header_key": old,
        },
        {
            "source_sha256": "b" * 64,
            "status": "failed",
            "header_sha256": "",
            "size_of_headers": "",
            "header_key": "",
        },
    ]
    with manifest.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    output = tmp_path / "out"
    if corrupt:
        with pytest.raises(ValueError, match="digest/size"):
            migrate_headers(manifest, "synthetic", output, 2)
        assert objects[new] == b"wrong"
    else:
        report = migrate_headers(manifest, "synthetic", output, 2)
        assert report["verified"] == 1
        assert report["failures_retained"] == 1
        assert objects[old] == objects[new] == payload
        migrate_headers(manifest, "synthetic", output, 2)
        assert len(copies) == 1
