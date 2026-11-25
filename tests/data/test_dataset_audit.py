"""Integration tests for the header-first native/.NET dataset audit.

Fixtures run through the real ``pefile``/``dnfile`` implementations against a fake
S3 transport; parser behaviour is never mocked. Two cases double as the documented
predicate experiments (empty tables stream, extended ``#Pdb`` stream).
"""

from __future__ import annotations

import csv
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import struct
from threading import Barrier

from botocore.exceptions import ClientError, ReadTimeoutError
import pytest

from malweave.data import dataset_audit as da
from malweave.data.audit_reporting import audit_status, export_dataset_audit

# ---------------------------------------------------------------------------
# Synthetic PE builders (real bytes, identity RVA mapping so dnfile resolves
# metadata through pefile's section logic exactly like a natural image).
# ---------------------------------------------------------------------------


def _metadata_root(streams: dict[str, bytes], version: bytes = b"v4.0.30319") -> bytes:
    vlen = (len(version) + 1 + 3) & ~3
    vdata = version + b"\x00" * (vlen - len(version))
    prefix_len = 16 + vlen + 4 + sum(8 + ((len(name) + 1 + 3) & ~3) for name in streams)
    headers = bytearray()
    datas = bytearray()
    cursor = prefix_len
    for name, data in streams.items():
        name_len = (len(name) + 1 + 3) & ~3
        headers += struct.pack("<II", cursor, len(data))
        headers += name.encode() + b"\x00" * (name_len - len(name))
        cursor += len(data)
        datas += data
    root = bytearray()
    root += b"BSJB" + struct.pack("<HHII", 1, 1, 0, vlen) + vdata
    root += struct.pack("<HH", 0, len(streams))
    root += headers
    root += datas
    return bytes(root)


def _tables_stream(module_row: bool) -> bytes:
    header = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 0, 1 if module_row else 0, 0)
    if module_row:
        row_counts = struct.pack("<I", 1)
        # Module row: Generation(2) Name(2) Mvid(2) EncId(2) EncBaseId(2), heap sizes 0
        row = struct.pack("<HHHHH", 0, 1, 1, 0, 0)
        return header + row_counts + row
    return header


GUID_HEAP = bytes(16)
STRINGS_HEAP = b"\x00Test\x00"
EMPTY_HEAP = b"\x00"


def _pe_bytes(
    *,
    managed: bool = False,
    pe64: bool = False,
    empty_tables: bool = False,
    pdb_stream: bool = False,
    clr_dir_va: int | None = None,
    garbage_metadata: bool = False,
) -> bytes:
    size = 0x900
    content = bytearray(size)
    content[:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", content, 0x3C, pe_off)
    content[pe_off : pe_off + 4] = b"PE\0\0"
    file_header = pe_off + 4
    machine, opt_size, opt_magic = (0x8664, 0xF0, 0x20B) if pe64 else (0x14C, 0xE0, 0x10B)
    struct.pack_into("<H", content, file_header, machine)
    struct.pack_into("<H", content, file_header + 2, 1)
    struct.pack_into("<H", content, file_header + 16, opt_size)
    optional = file_header + 20
    struct.pack_into("<H", content, optional, opt_magic)
    struct.pack_into("<I", content, optional + 60, 0x400)  # SizeOfHeaders
    struct.pack_into("<I", content, optional + (108 if pe64 else 92), 16)
    section_table = optional + opt_size
    section = section_table
    content[section : section + 8] = b".text"
    struct.pack_into("<I", content, section + 8, 0x500)  # VirtualSize
    struct.pack_into("<I", content, section + 12, 0x400)  # VirtualAddress
    struct.pack_into("<I", content, section + 16, 0x500)  # SizeOfRawData
    struct.pack_into("<I", content, section + 20, 0x400)  # PointerToRawData
    struct.pack_into("<I", content, section + 36, 0x60000020)

    if not managed:
        return bytes(content)

    streams: dict[str, bytes] = {
        "#~": _tables_stream(module_row=not empty_tables),
        "#Strings": STRINGS_HEAP,
        "#US": EMPTY_HEAP,
        "#GUID": GUID_HEAP,
        "#Blob": EMPTY_HEAP,
    }
    if pdb_stream:
        streams["#Pdb"] = struct.pack("<I16s", 1, bytes(16))
    root = _metadata_root(streams)
    if garbage_metadata:
        root = b"\x00" * len(root)

    metadata_rva = 0x500
    dir_va = 0x400 if clr_dir_va is None else clr_dir_va
    directory = optional + (112 if pe64 else 96) + 14 * 8
    struct.pack_into("<II", content, directory, dir_va, 72)
    # IMAGE_COR20_HEADER: cb, runtime 2.5, metadata RVA/size, flags ILONLY, entrypoint
    struct.pack_into("<IHH", content, 0x400, 72, 2, 5)
    struct.pack_into("<II", content, 0x408, metadata_rva, len(root))
    struct.pack_into("<II", content, 0x410, 1, 0)
    content[0x500 : 0x500 + len(root)] = root
    return bytes(content)


# ---------------------------------------------------------------------------
# Fake transport
# ---------------------------------------------------------------------------


class FakeBody(BytesIO):
    def __init__(self, data: bytes, fail: bool = False):
        super().__init__(data)
        self.fail = fail

    def read(self, size: int = -1) -> bytes:
        if self.fail and (size == -1 or self.tell() > 0):
            raise ReadTimeoutError(endpoint_url="https://example.invalid")
        return super().read(size)


class FakeS3:
    def __init__(self, objects: dict[str, bytes]):
        self.objects = objects
        self.etags = {key: f'"etag-{index}"' for index, key in enumerate(objects)}
        self.calls: list[tuple[str, str]] = []
        self.offline = False
        self.version_flip = False
        self.body_errors = set()
        self.bodies = []

    def get_object(self, Bucket=None, Key=None, IfMatch=None, Range=None, **_kw):
        assert Range is None
        self.calls.append(("full", Key))
        if self.offline:
            raise RuntimeError("offline")
        if self.version_flip or (IfMatch is not None and IfMatch != self.etags[Key]):
            raise ClientError(
                {"Error": {"Code": "PreconditionFailed", "Message": "412"}}, "GetObject"
            )
        buf = self.objects[Key]
        etag = self.etags[Key]
        body = FakeBody(buf, fail=Key in self.body_errors)
        self.bodies.append(body)
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "ETag": etag,
            "ContentLength": len(buf),
            "Body": body,
        }


@pytest.fixture
def audit_env(monkeypatch, tmp_path):
    """Patch the transport and loader; return (run, job_dir, client)."""

    def install(objects: dict[str, bytes], rows: list[dict]):
        client = FakeS3(objects)
        monkeypatch.setattr(da, "_s3_client", lambda profile=None: client)
        rows = [{**row, "etag": client.etags[row["key"]], "bucket": "bucket"} for row in rows]
        monkeypatch.setattr(da, "load_sources_csv", lambda dataset: (rows, {}))

        def run(**kwargs):
            kwargs.setdefault("job_dir", tmp_path / "job")
            kwargs.setdefault("dataset", "vera")
            return da.run_dataset_audit(**kwargs)

        return run, tmp_path / "job", client

    return install


def _row(content: bytes, name: str = "a.bin", *, expected_sha256: str | None = None) -> dict:
    key = f"vera/zenodo-v1/binaries/active/00/{name}"
    return {
        "dataset": "vera",
        "sha256": expected_sha256 or sha256(content).hexdigest(),
        "bucket": "bucket",
        "key": key,
        "size": len(content),
        "etag": "",
        "label": "active",
        "extra": {},
    }


def _labels(job_dir: Path) -> dict[str, tuple[str, str]]:
    db = sqlite3.connect(f"file:{job_dir / 'state.sqlite3'}?mode=ro", uri=True)
    return {
        sha: (label or "", reason or "")
        for sha, label, reason in db.execute("SELECT sha256, label, reason FROM result")
    }


# ---------------------------------------------------------------------------
# PE header and CLR metadata
# ---------------------------------------------------------------------------


def test_native_pe32_is_labeled_without_clr_parse(audit_env):
    content = _pe_bytes(managed=False)
    rows = [_row(content, "0" * 64)]
    run, job_dir, client = audit_env({rows[0]["key"]: content}, rows)
    run()
    labels = _labels(job_dir)
    assert labels[rows[0]["sha256"]] == ("native", "clr_directory_absent")
    assert client.calls == [("full", rows[0]["key"])]


def test_metadata_evidence_is_only_written_for_clr_sources(audit_env):
    native = _pe_bytes(managed=False)
    managed = _pe_bytes(managed=True)
    rows = [_row(native, "d" * 64), _row(managed, "e" * 64)]
    run, job_dir, _client = audit_env({rows[0]["key"]: native, rows[1]["key"]: managed}, rows)
    run()
    labels = _labels(job_dir)
    assert labels[rows[0]["sha256"]] == ("native", "clr_directory_absent")
    assert labels[rows[1]["sha256"]] == ("dotnet", "metadata_validated")
    db = sqlite3.connect(f"file:{job_dir / 'state.sqlite3'}?mode=ro", uri=True)
    native_row = db.execute(
        "SELECT stage_b, clr_present FROM result WHERE sha256=?", (rows[0]["sha256"],)
    ).fetchone()
    assert native_row[0] is None
    assert native_row[1] == 0


def test_native_pe32plus_is_labeled(audit_env):
    content = _pe_bytes(managed=False, pe64=True)
    rows = [_row(content, "1" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    assert _labels(job_dir)[rows[0]["sha256"]] == ("native", "clr_directory_absent")


def test_dotnet_validates_with_full_metadata(audit_env):
    content = _pe_bytes(managed=True)
    rows = [_row(content, "2" * 64)]
    run, job_dir, client = audit_env({rows[0]["key"]: content}, rows)
    run()
    assert client.calls == [("full", rows[0]["key"])]
    labels = _labels(job_dir)
    assert labels[rows[0]["sha256"]] == ("dotnet", "metadata_validated")
    db = sqlite3.connect(f"file:{job_dir / 'state.sqlite3'}?mode=ro", uri=True)
    streams = json.loads(db.execute("SELECT stage_b FROM result").fetchone()[0])["streams"]
    assert "#~" in streams and "#Strings" in streams


def test_clr_dir_present_but_unmapped_is_dotnet_invalid(audit_env):
    content = _pe_bytes(managed=True, clr_dir_va=0x4000)  # unmapped CLR header RVA
    rows = [_row(content, "3" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    label, reason = _labels(job_dir)[rows[0]["sha256"]]
    assert label == "dotnet_invalid"
    assert reason == "invalid_clr_header"


def test_garbage_metadata_is_malformed(audit_env):
    content = _pe_bytes(managed=True, garbage_metadata=True)
    rows = [_row(content, "4" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    label, reason = _labels(job_dir)[rows[0]["sha256"]]
    assert label == "dotnet_invalid"
    assert reason == "malformed_metadata"


def test_truncated_header_is_insufficient(audit_env):
    content = b"MZ" + b"\x00" * 30  # e_lfanew missing entirely
    rows = [_row(content, "5" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    assert _labels(job_dir)[rows[0]["sha256"]] == ("unknown", "insufficient_header_data")


def test_invalid_pe_header_is_unknown(audit_env):
    content = bytearray(_pe_bytes(managed=False))
    content[0x80:0x84] = b"NOPE"  # broken PE signature at e_lfanew
    rows = [_row(bytes(content), "6" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    assert _labels(job_dir)[rows[0]["sha256"]] == ("unknown", "invalid_pe_header")


@pytest.mark.parametrize("pe64", [False, True], ids=["pe32", "pe32plus"])
@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("truncated_directories", "incomplete_pe_data_directories"),
        ("undersized_optional_header", "incomplete_pe_data_directories"),
        ("truncated_section_table", "incomplete_pe_section_table"),
        ("partial_section_record", "invalid_pe_header"),
        ("missing_clr_address", "inconsistent_clr_directory"),
        ("missing_clr_size", "inconsistent_clr_directory"),
        ("undeclared_clr_slot", "clr_directory_absent"),
    ],
)
def test_full_audit_requires_complete_consistent_header(audit_env, pe64, case, reason):
    content = bytearray(_pe_bytes(pe64=pe64))
    nt = struct.unpack_from("<I", content, 0x3C)[0]
    optional = nt + 24
    directory_base = 112 if pe64 else 96
    clr_slot = optional + directory_base + 14 * 8
    if case == "truncated_directories":
        del content[clr_slot:]
    elif case == "undersized_optional_header":
        struct.pack_into("<H", content, nt + 20, directory_base + 14 * 8)
    elif case in {"truncated_section_table", "partial_section_record"}:
        optional_size = struct.unpack_from("<H", content, nt + 20)[0]
        remaining = 39 if case == "partial_section_record" else 0
        del content[optional + optional_size + remaining :]
    elif case == "missing_clr_address":
        struct.pack_into("<II", content, clr_slot, 0, 72)
    elif case == "missing_clr_size":
        struct.pack_into("<II", content, clr_slot, 0x400, 0)
    else:
        struct.pack_into("<I", content, optional + directory_base - 4, 14)

    data = bytes(content)
    source = _row(data, sha256(data).hexdigest())
    run, job_dir, client = audit_env({source["key"]: data}, [source])
    summary = run()
    label = "native" if case == "undeclared_clr_slot" else "unknown"
    assert summary["by_label"] == {label: 1}
    assert _labels(job_dir)[source["sha256"]] == (label, reason)
    with sqlite3.connect(job_dir / "state.sqlite3") as db:
        a, b, clr_present = db.execute(
            "SELECT stage_a, stage_b, clr_present FROM result"
        ).fetchone()
    evidence = json.loads(a)
    assert b is None
    assert clr_present == (0 if label == "native" else None)
    assert client.calls == [("full", source["key"])]
    if case == "missing_clr_address":
        assert (evidence["dir14_va"], evidence["dir14_size"]) == (0, 72)
    elif case == "missing_clr_size":
        assert (evidence["dir14_va"], evidence["dir14_size"]) == (0x400, 0)
    elif case == "undeclared_clr_slot":
        assert evidence["declared_directory_count"] == 14
        assert evidence["clr_directory_declared"] is False
    else:
        assert "dir14_va" not in evidence


def test_resume_preserves_equivalent_full_file_results(audit_env):
    native = _pe_bytes()
    managed = _pe_bytes(managed=True)
    rows = [_row(native, "native.bin"), _row(managed, "managed.bin")]
    run, job_dir, client = audit_env({rows[0]["key"]: native, rows[1]["key"]: managed}, rows)
    assert run(limit=1)["finalized"] == 1
    with sqlite3.connect(job_dir / "state.sqlite3") as db:
        identity = json.loads(
            db.execute("SELECT value FROM job WHERE key='identity'").fetchone()[0]
        )
        identity.update(
            method="pe-full-file-dnfile-v2",
            pipeline_version="dataset-audit-v2",
            download_mode="full_file",
        )
        receipt = json.dumps(identity)
        db.execute("UPDATE job SET value=? WHERE key='identity'", (receipt,))
    assert json.loads(audit_status(job_dir))["method"] == "native-dotnet"
    assert run()["by_label"] == {"native": 1, "dotnet": 1}
    assert client.calls == [("full", row["key"]) for row in rows]
    with sqlite3.connect(job_dir / "state.sqlite3") as db:
        assert db.execute("SELECT value FROM job WHERE key='identity'").fetchone()[0] == receipt
        identity.update(method="pe-full-file-dnfile-v1", pipeline_version="dataset-audit-v1")
        db.execute("UPDATE job SET value=? WHERE key='identity'", (json.dumps(identity),))
    assert json.loads(audit_status(job_dir))["method"] == "historical-audit"
    with pytest.raises(da.SorelError, match="Audit inputs/identity changed"):
        run()
    assert len(client.calls) == 2


def test_experiment_empty_tables_stream(audit_env):
    content = _pe_bytes(managed=True, empty_tables=True)
    rows = [_row(content, "8" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    label, reason = _labels(job_dir)[rows[0]["sha256"]]
    assert label == "dotnet" and reason == "metadata_validated"


def test_experiment_pdb_stream_is_accepted(audit_env):
    content = _pe_bytes(managed=True, pdb_stream=True)
    rows = [_row(content, "9" * 64)]
    run, job_dir, _ = audit_env({rows[0]["key"]: content}, rows)
    run()
    label, reason = _labels(job_dir)[rows[0]["sha256"]]
    assert label == "dotnet" and reason == "metadata_validated"
    db = sqlite3.connect(f"file:{job_dir / 'state.sqlite3'}?mode=ro", uri=True)
    streams = json.loads(db.execute("SELECT stage_b FROM result").fetchone()[0])["streams"]
    assert "#Pdb" in streams


# ---------------------------------------------------------------------------
# Transport semantics
# ---------------------------------------------------------------------------


def test_transport_error_is_retryable_and_never_dotnet_invalid(audit_env):
    content = _pe_bytes(managed=True)
    rows = [_row(content, "a" * 64)]
    run, job_dir, client = audit_env({rows[0]["key"]: content}, rows)
    client.offline = True
    run(retry_errors=True)
    assert _labels(job_dir)[rows[0]["sha256"]] == ("unknown", "download_failed")
    db = sqlite3.connect(f"file:{job_dir / 'state.sqlite3'}?mode=ro", uri=True)
    assert db.execute("SELECT status FROM result").fetchone()[0] == "transport_error"
    client.offline = False
    run(retry_errors=True)
    assert _labels(job_dir)[rows[0]["sha256"]] == ("dotnet", "metadata_validated")


def test_version_mismatch_discards_and_requeues(audit_env):
    content = _pe_bytes(managed=True)
    rows = [_row(content)]
    run, job_dir, client = audit_env({rows[0]["key"]: content}, rows)
    client.version_flip = True
    assert run()["version_mismatches"] == 1
    with sqlite3.connect(job_dir / "state.sqlite3") as db:
        assert db.execute("SELECT status, stage_a, stage_b FROM result").fetchone() == (
            "version_mismatch",
            None,
            None,
        )
    client.version_flip = False
    run()
    assert _labels(job_dir)[rows[0]["sha256"]] == ("dotnet", "metadata_validated")


def test_job_progress_and_csv_export(audit_env, tmp_path):
    native = _pe_bytes(managed=False)
    managed = _pe_bytes(managed=True)
    rows = [_row(native, "1" * 64), _row(managed, "2" * 64)]
    run, job_dir, client = audit_env({rows[0]["key"]: native, rows[1]["key"]: managed}, rows)
    output = tmp_path / "native-dotnet.csv"

    summary = run(limit=1)
    status = json.loads(audit_status(job_dir))
    assert status["awaiting"] == 1
    assert status["finalized"] == 1
    assert summary["pending"] == 1
    with pytest.raises(da.SorelError, match="1 unresolved sources"):
        export_dataset_audit(job_dir, output)
    assert not output.exists()

    client.offline = True
    summary = run()
    assert summary["retryable_errors"] == 1
    assert summary["awaiting"] == 0
    assert summary["pending"] == 1
    client.offline = False
    summary = run(retry_errors=True)
    assert summary["finalized"] == 2
    assert summary["pending"] == 0

    # An older job may have recorded only Machine and a PE32+ flag.
    with sqlite3.connect(job_dir / "state.sqlite3") as db:
        db.execute(
            "UPDATE result SET stage_a = json_remove(stage_a, '$.optional_header_magic') "
            "WHERE sha256 = ?",
            (rows[0]["sha256"],),
        )
    calls = list(client.calls)
    assert export_dataset_audit(job_dir, output)["rows"] == 2
    with output.open(newline="") as stream:
        records = list(csv.DictReader(stream))
    assert client.calls == calls
    assert [(r["source_label"], r["label"], r["clr_present"]) for r in records] == [
        ("active", "native", "0"),
        ("active", "dotnet", "1"),
    ]
    assert records[0]["optional_header_magic"] == ""
    assert records[1]["optional_header_magic"] == str(0x10B)
    assert records[1]["machine"] == str(0x14C)
    with pytest.raises(da.SorelError, match="already exists"):
        export_dataset_audit(job_dir, output)


def test_default_full_mode_has_16_concurrent_downloads_and_cleans_up(audit_env, monkeypatch):
    native = _pe_bytes(managed=False)
    managed = _pe_bytes(managed=True)
    payloads = [native + bytes([i]) for i in range(16)] + [managed]
    rows = [_row(data, sha256(data).hexdigest()) for data in payloads]
    run, job_dir, client = audit_env(
        {row["key"]: data for row, data in zip(rows, payloads, strict=True)}, rows
    )
    peaks = []
    network_barrier = Barrier(
        16, timeout=5, action=lambda: peaks.append(len(list(job_dir.glob(".audit-pe-*.tmp"))))
    )
    all_but_last = {row["key"] for row in rows[:16]}
    original_get = client.get_object
    active_parser = []
    dn_pe = da.dnfile.dnPE

    def start_download(**kwargs):
        if kwargs["Key"] in all_but_last:
            network_barrier.wait()
        return original_get(**kwargs)

    def parse_managed(**kwargs):
        path = Path(kwargs["name"])
        assert path.is_file() and sha256(path.read_bytes()).hexdigest() == rows[-1]["sha256"]
        active_parser.append(path)
        return dn_pe(**kwargs)

    monkeypatch.setattr(client, "get_object", start_download)
    monkeypatch.setattr(da.dnfile, "dnPE", parse_managed)
    summary = run()
    assert max(peaks) == 16
    assert summary["by_label"] == {"native": 16, "dotnet": 1}
    assert summary["method"] == "native-dotnet"
    assert summary["awaiting"] == 0 and summary["finalized"] == 17
    assert len(active_parser) == 1 and not active_parser[0].exists()
    assert not list(job_dir.glob(".audit-pe-*.tmp"))
    assert sorted(client.calls) == sorted(("full", row["key"]) for row in rows)
    assert json.loads(audit_status(job_dir))["current_run"]["bytes_downloaded"] == sum(
        len(data) for data in payloads
    )
    assert run()["pending"] == 0
    assert len(client.calls) == 17


def test_full_body_timeout_tracks_failure_retries_only_that_source(audit_env):
    good = _pe_bytes(managed=False)
    slow = _pe_bytes(managed=True)
    rows = [_row(good, sha256(good).hexdigest()), _row(slow, sha256(slow).hexdigest())]
    run, job_dir, client = audit_env({rows[0]["key"]: good, rows[1]["key"]: slow}, rows)
    client.body_errors.add(rows[1]["key"])

    summary = run()
    assert summary["finalized"] == 1 and summary["retryable_errors"] == 1
    assert _labels(job_dir)[rows[1]["sha256"]] == ("unknown", "download_failed")
    assert all(body.closed for body in client.bodies)
    assert not list(job_dir.glob(".audit-pe-*.tmp"))

    client.body_errors.clear()
    assert run(retry_errors=True)["by_label"] == {"native": 1, "dotnet": 1}
    assert client.calls.count(("full", rows[0]["key"])) == 1
    assert client.calls.count(("full", rows[1]["key"])) == 2


def test_inventory_digest_mismatch_never_reaches_pe_parser(audit_env, monkeypatch):
    data = _pe_bytes(managed=False)
    rows = [_row(data, expected_sha256="0" * 64)]
    run, job_dir, client = audit_env({rows[0]["key"]: data}, rows)

    def unexpected_parse(*args, **kwargs):
        pytest.fail("a mismatched object must not be parsed")

    monkeypatch.setattr(da.pefile, "PE", unexpected_parse)
    summary = run()
    assert summary["version_mismatches"] == 1 and summary["finalized"] == 0
    assert summary["by_reason"] == {"source_sha256_mismatch": 1}
    assert client.bodies[0].closed and not list(job_dir.glob(".audit-pe-*.tmp"))


def test_resume_is_idempotent(audit_env):
    content = _pe_bytes(managed=False)
    rows = [_row(content, "c" * 64)]
    run, _job_dir, client = audit_env({rows[0]["key"]: content}, rows)
    first = run()
    calls_after_first = len(client.calls)
    second = run()
    assert len(client.calls) == calls_after_first
    assert second["pending"] == 0 == first["pending"]
    assert second["by_label"] == first["by_label"]


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


def test_finished_job_survives_wal_removal(audit_env):
    """Regression: a completed run must checkpoint its WAL into state.sqlite3, so
    copying/moving the job (or losing -wal/-shm) cannot lose results."""
    content = _pe_bytes(managed=False)
    rows = [_row(content, "f" * 64)]
    run, job_dir, _client = audit_env({rows[0]["key"]: content}, rows)
    run()
    for suffix in ("-wal", "-shm"):
        wal = Path(str(job_dir / "state.sqlite3") + suffix)
        if wal.exists():
            wal.unlink()
    db = sqlite3.connect(f"file:{job_dir / 'state.sqlite3'}?mode=ro", uri=True)
    count = db.execute("SELECT COUNT(*) FROM result").fetchone()[0]
    db.close()
    assert count == 1


def test_load_sources_csv_reads_and_validates(tmp_path, monkeypatch):
    csv_path = tmp_path / "files.csv"
    csv_path.write_text(
        "sha256,s3_key,size,etag,label,clr_present,machine\n"
        + f'{"a" * 64},raw/00/{"a" * 64},100,"etag-1",benign,0,0x14c\n'
        + f'{"b" * 64},raw/01/{"b" * 64},200,"etag-2",,1,0x8664\n'
    )
    monkeypatch.setitem(
        da.DATASETS,
        "assemblage",
        {"bucket": "assemblage-malware-research-x", "inventory_csv": str(csv_path)},
    )
    rows, excluded = da.load_sources_csv("assemblage")
    assert len(rows) == 2
    assert rows[0]["label"] == "benign"
    assert rows[0]["extra"]["clr_present"] == "0"
    assert rows[1]["extra"]["machine"] == "0x8664"
    assert excluded == {}

    bad = tmp_path / "bad.csv"
    bad.write_text("sha256,s3_key,size,etag\n" + 'zz,raw/00/x,1,"e"\n')
    monkeypatch.setitem(
        da.DATASETS,
        "assemblage",
        {"bucket": "b", "inventory_csv": str(bad)},
    )
    with pytest.raises(da.SorelError, match="invalid sha256"):
        da.load_sources_csv("assemblage")
