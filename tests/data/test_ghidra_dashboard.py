"""Synthetic-only monitor tests: status semantics, privacy and loopback access."""

from datetime import datetime, timezone
from http.client import HTTPConnection
import io
import json
import threading

import pytest

from malweave import cli
from malweave.data import ghidra_dashboard as dashboard
from malweave.data.sorel import SorelError

NOW = 10000.0
JOB = dashboard.Job(
    "test-account",
    "Batch 1",
    "analysis/private-batches/synthetic/batch-1/workers-21/benchmark-report.json",
    "synthetic-batch-1",
)


def report():
    return {
        "status": "running",
        "source_count": 4,
        "seconds": 300,
        "resources": {"sampled_process_tree_peak_rss_bytes": 2 * 1024**3},
        "results": [
            {
                "source_sha256": "PRIVATE-SOURCE-ID",
                "views": [
                    {
                        "view": "dis",
                        "status": "success",
                        "representation_sha256": "PRIVATE-DIGEST",
                        "execution": {"stderr": "https://private.example/?token=SECRET"},
                    },
                    {
                        "view": "dec",
                        "status": "success",
                        "representation_sha256": "PRIVATE-DIGEST",
                    },
                ],
            },
            {
                "views": [
                    {"view": "dis", "status": "success", "representation_sha256": "PRIVATE"},
                    {"view": "dec", "status": "partial_error"},
                ]
            },
            {"views": [], "error_type": "PRIVATE-ERROR"},
        ],
        "inflight": {"PRIVATE-INDEX": {"published_views": ["dis"]}},
    }


class Client:
    def __init__(self):
        self.fail = False
        self.reads = []

    def get_object(self, **kwargs):
        self.reads.append(kwargs)
        if self.fail:
            raise RuntimeError("https://private.example/SECRET")
        return {
            "Body": io.BytesIO(json.dumps(report()).encode()),
            "LastModified": datetime.fromtimestamp(NOW, timezone.utc),
        }


def test_report_aggregates_without_leaking_source_evidence():
    summary = dashboard.summarize_report(report(), datetime.fromtimestamp(NOW, timezone.utc), NOW)
    assert summary["done"] == 3
    assert summary["total"] == 4
    assert summary["clean"] == 1
    assert summary["partial_failed"] == 2
    assert summary["no_success"] == 1
    assert summary["dis_success"] == 2
    assert summary["dec_success"] == 1
    assert summary["published_views"] == 3
    assert summary["dis_checkpointed"] == 1
    assert summary["peak_process_rss_gib"] == 2
    serialized = json.dumps(summary)
    assert "PRIVATE" not in serialized
    assert "SECRET" not in serialized
    assert "https://" not in serialized


def test_deferred_managed_sources_are_pending_not_success_or_final_coverage():
    data = {
        "status": "partial",
        "source_count": 1,
        "seconds": 1,
        "results": [
            {
                "source_sha256": "a" * 64,
                "pending": True,
                "routing": {"route": "managed_pending", "metadata_version": "PRIVATE"},
                # Even a contradictory success marker cannot count as managed coverage.
                "views": [{"view": "dis", "status": "success"}],
            }
        ],
    }
    summary = dashboard.summarize_report(data, datetime.fromtimestamp(NOW, timezone.utc), NOW)
    assert summary["deferred_pending"] == 1
    assert summary["clean"] == summary["partial_failed"] == summary["dis_success"] == 0
    coverage = dashboard.source_coverage(data)
    assert coverage["pending"] == {"a" * 64}
    assert coverage["done"] == coverage["dis"] == coverage["dec"] == set()
    monitor = dashboard.Monitor(Client(), "private-bucket", [JOB], pool=("P1", 10))
    monitor.records[JOB.report_key] = {"summary": summary, "coverage": coverage}
    snapshot = monitor.snapshot(NOW)
    assert snapshot["pool"]["remaining"] == 10
    assert snapshot["pool"]["deferred_pending"] == 1
    assert "PRIVATE" not in json.dumps(snapshot)


def test_pool_filters_historical_success_to_pinned_native_membership():
    member, outside = "b" * 64, "c" * 64
    monitor = dashboard.Monitor(Client(), "private", [JOB], pool=("P1", 1), pool_members={member})
    monitor.records[JOB.report_key] = {
        "coverage": {
            "done": {member, outside},
            "dis": {member, outside},
            "dec": {member, outside},
        }
    }
    pool = monitor.snapshot(NOW)["pool"]
    assert pool["done"] == pool["both_success"] == 1
    assert pool["remaining"] == 0
    assert outside not in json.dumps(monitor.snapshot(NOW))


def test_dotnet_exclusion_overrides_old_success_without_erasing_evidence():
    source = "b" * 64
    data = {
        "status": "completed_with_exclusions",
        "source_count": 1,
        "results": [{"source_sha256": source, "excluded": True, "views": []}],
    }
    summary = dashboard.summarize_report(data, datetime.fromtimestamp(NOW, timezone.utc), NOW)
    assert summary["excluded_dotnet"] == 1
    assert summary["reported_status"] == "completed_with_exclusions"
    assert summary["partial_failed"] == summary["clean"] == 0
    monitor = dashboard.Monitor(Client(), "private", [JOB], pool=("P1", 10))
    monitor.records[JOB.report_key] = {
        "summary": summary,
        "coverage": dashboard.source_coverage(data),
    }
    monitor.records["historical"] = {
        "coverage": {
            "done": {source},
            "dis": {source},
            "dec": {source},
        }
    }
    pool = monitor.snapshot(NOW)["pool"]
    assert pool["excluded_dotnet"] == 1
    assert pool["done"] == pool["both_success"] == 0
    assert pool["remaining"] == 9


def test_heartbeat_is_not_kaggle_liveness(monkeypatch):
    monkeypatch.setattr(dashboard.time, "time", lambda: NOW)
    monitor = dashboard.Monitor(Client(), "private-bucket", [JOB])
    assert monitor.snapshot(NOW)["jobs"][0]["state"] == "waiting"
    monitor.refresh()
    row = monitor.snapshot(NOW + 50)["jobs"][0]
    assert row["state"] == "fresh"
    assert row["notebook_url"].startswith("https://www.kaggle.com/code/test-account/")
    assert monitor.snapshot(NOW + 181)["jobs"][0]["state"] == "cache_stale"
    # A freshly fetched but old running report is stale, never labelled running/live.
    monkeypatch.setattr(dashboard.time, "time", lambda: NOW + 1000)
    monitor.refresh()
    row = monitor.snapshot(NOW + 1000)["jobs"][0]
    assert row["state"] == "stale"
    assert row["heartbeat_age_s"] == 1000


def test_fetch_failure_keeps_counts_but_marks_cache_unavailable(monkeypatch):
    monkeypatch.setattr(dashboard.time, "time", lambda: NOW)
    client = Client()
    monitor = dashboard.Monitor(client, "private-bucket", [JOB])
    monitor.refresh()
    client.fail = True
    monitor.refresh()
    row = monitor.snapshot(NOW)["jobs"][0]
    assert row["state"] == "unavailable"
    assert row["done"] == 3
    assert "SECRET" not in json.dumps(monitor.snapshot(NOW))
    assert JOB.report_key not in json.dumps(monitor.snapshot(NOW))
    # Browser snapshots do not trigger any S3 calls.
    assert len(client.reads) == 2


def test_timeout_with_none_response_preserves_cache_and_allows_recovery(monkeypatch):
    from botocore.exceptions import ReadTimeoutError

    class TimeoutClient(Client):
        def get_object(self, **kwargs):
            if self.fail:
                raise ReadTimeoutError(endpoint_url="https://SECRET.invalid/private")
            return super().get_object(**kwargs)

    monkeypatch.setattr(dashboard.time, "time", lambda: NOW)
    client = TimeoutClient()
    monitor = dashboard.Monitor(client, "private-bucket", [JOB])
    monitor.refresh()
    client.fail = True
    monitor.refresh()
    row = monitor.snapshot(NOW)["jobs"][0]
    assert row["state"] == "unavailable"
    assert row["done"] == 3
    assert "SECRET" not in json.dumps(monitor.snapshot(NOW))
    client.fail = False
    monitor.refresh()
    assert monitor.snapshot(NOW)["jobs"][0]["fetch_error"] is None


def test_conditional_get_304_refreshes_cache_without_downloading_or_losing_coverage(monkeypatch):
    from botocore.exceptions import ClientError

    class ConditionalClient(Client):
        def get_object(self, **kwargs):
            if kwargs.get("IfNoneMatch"):
                self.reads.append(kwargs)
                assert kwargs["IfNoneMatch"] == '"synthetic-etag"'
                raise ClientError(
                    {"Error": {"Code": "304"}, "ResponseMetadata": {"HTTPStatusCode": 304}},
                    "GetObject",
                )
            return {**super().get_object(**kwargs), "ETag": '"synthetic-etag"'}

    monkeypatch.setattr(dashboard.time, "time", lambda: NOW)
    client = ConditionalClient()
    monitor = dashboard.Monitor(client, "private-bucket", [JOB], pool=("P1", 70028))
    monitor.refresh()
    monkeypatch.setattr(dashboard.time, "time", lambda: NOW + 1000)
    monitor.refresh()
    row = monitor.snapshot(NOW + 1000)["jobs"][0]
    assert row["state"] == "stale"  # Report old; S3 connection/cache healthy.
    assert row["fetch_age_s"] == 0
    assert row["done"] == 3
    assert row["fetch_error"] is None
    assert monitor.snapshot(NOW + 1000)["pool"]["unknown_identity_rows"] == 3
    assert len(client.reads) == 2
    assert "synthetic-etag" not in json.dumps(monitor.snapshot(NOW + 1000))


def test_historical_cache_has_its_own_refresh_budget(monkeypatch):
    monkeypatch.setattr(dashboard.time, "time", lambda: NOW)
    old = dashboard.Job(JOB.account, JOB.name, JOB.report_key, JOB.slug, historical=True)
    monitor = dashboard.Monitor(Client(), "private-bucket", [old])
    monitor.refresh()
    snapshot = monitor.snapshot(NOW + 1000)
    assert snapshot["history_refresh_seconds"] == 900
    assert snapshot["jobs"][0]["state"] == "stale"  # Not a spurious 3-minute read error.


def test_history_pool_does_not_block_current_job_refresh(monkeypatch):
    history_started, current_fetched, release_history = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    old = dashboard.Job(
        "old",
        "History",
        JOB.report_key.replace("batch-1", "batch-old"),
        "history",
        historical=True,
    )
    monitor = dashboard.Monitor(Client(), "private-bucket", [old, JOB])

    def fetch(job):
        if job.historical:
            history_started.set()
            assert release_history.wait(timeout=5)
        else:
            current_fetched.set()

    monkeypatch.setattr(monitor, "_fetch", fetch)
    thread = threading.Thread(target=monitor.run, daemon=True)
    thread.start()
    try:
        assert history_started.wait(timeout=5)
        assert current_fetched.wait(timeout=5)  # History remains blocked.
    finally:
        monitor.stop.set()
        release_history.set()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_first_fetch_failure_does_not_invent_zero_progress():
    client = Client()
    client.fail = True
    monitor = dashboard.Monitor(client, "private-bucket", [JOB])
    monitor.refresh()
    row = monitor.snapshot()["jobs"][0]
    assert row["state"] == "unavailable"
    assert "done" not in row
    assert "total" not in row


def test_global_pool_deduplicates_old_and_resume_sources_without_exposing_hashes():
    sha, other = f"{1:064x}", f"{2:064x}"
    old = dashboard.Job("old", "Batch", JOB.report_key, "batch", historical=True)
    new = dashboard.Job(
        "new",
        "Resume",
        JOB.report_key.replace("batch-1", "resume-1"),
        "resume",
    )
    monitor = dashboard.Monitor(Client(), "private-bucket", [old, new], pool=("P1", 70028))
    first = {
        **report(),
        "results": [
            {"source_sha256": sha, "views": [{"view": "dis", "status": "success"}]},
            {"source_sha256": other, "views": []},
        ],
    }
    second = {
        **report(),
        "results": [
            {"source_sha256": sha, "views": [{"view": "dec", "status": "success"}]},
        ],
    }
    for job, data in [(old, first), (new, second)]:
        monitor.records[job.report_key] = {
            "summary": dashboard.summarize_report(
                data, datetime.fromtimestamp(NOW, timezone.utc), NOW
            ),
            "coverage": dashboard.source_coverage(data),
            "fetch_error": None,
        }
    snapshot = monitor.snapshot(NOW)
    pool = snapshot["pool"]
    assert pool["done"] == 2  # Not 3 attempts, and includes hidden historical rows.
    assert pool["both_success"] == 1  # DIS and DEC may complete in separate attempts.
    assert pool["partial_failed_only"] == 1
    assert pool["remaining"] == 70026
    assert pool["reports_loaded"] == 2
    assert pool["unknown_identity_rows"] == 0
    assert sha not in json.dumps(snapshot)
    assert other not in json.dumps(snapshot)
    assert monitor.records[old.report_key]["coverage"]["done"] == {sha, other}


def test_pool_flags_missing_reports_unknown_identities_and_preserves_error_cache(monkeypatch):
    monkeypatch.setattr(dashboard.time, "time", lambda: NOW)
    client = Client()
    monitor = dashboard.Monitor(client, "private-bucket", [JOB], pool=("P1", 70028))
    assert monitor.snapshot(NOW)["pool"]["reports_loaded"] == 0
    monitor.refresh()
    pool = monitor.snapshot(NOW)["pool"]
    assert pool["unknown_identity_rows"] == 3
    assert pool["done"] == 0  # Never fabricate identities from row indices.
    client.fail = True
    monitor.refresh()
    assert monitor.snapshot(NOW)["pool"]["unknown_identity_rows"] == 3
    assert monitor.snapshot(NOW)["pool"]["unavailable_reports"] == 1


def test_pool_registry_requires_an_explicit_positive_total(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"jobs": []}))
    assert dashboard.load_pool(path) is None
    path.write_text(json.dumps({"pool": {"name": "P1", "total": 70028}}))
    assert dashboard.load_pool(path) == ("P1", 70028)
    for pool in [{"name": "P1", "total": -1}, {"name": "<script>", "total": 1}, {}]:
        path.write_text(json.dumps({"pool": pool}))
        with pytest.raises(SorelError, match="Invalid dashboard pool"):
            dashboard.load_pool(path)


@pytest.mark.parametrize("status", ["completed", "partial", "failed"])
def test_terminal_reports_do_not_become_running_when_fresh(status):
    summary = dashboard.summarize_report(
        {**report(), "status": status}, datetime.fromtimestamp(NOW, timezone.utc), NOW
    )
    monitor = dashboard.Monitor(Client(), "private-bucket", [JOB])
    monitor.records[JOB.report_key] = {"summary": summary, "fetch_error": None}
    assert monitor.snapshot(NOW + 10)["jobs"][0]["state"] == status


@pytest.mark.parametrize("total", [-1, True, "4", 2])
def test_invalid_reports_are_rejected(total):
    with pytest.raises(ValueError):
        dashboard.summarize_report(
            {**report(), "source_count": total}, datetime.fromtimestamp(NOW, timezone.utc), NOW
        )


def test_registry_validates_explicit_mapping_and_duplicates(tmp_path):
    path = tmp_path / "registry.json"
    entry = dict(vars(JOB))
    path.write_text(json.dumps({"jobs": [entry]}))
    assert dashboard.load_jobs(path) == [JOB]
    for entries in [
        [entry, entry],
        [{**entry, "account": "<script>"}],
        [{**entry, "report_key": "raw/source"}],
        [{**entry, "historical": "false"}],
        [{**entry, "report_key": JOB.report_key + "?secret=SECRET"}],
    ]:
        path.write_text(json.dumps({"jobs": entries}))
        with pytest.raises(SorelError, match="Invalid dashboard registry"):
            dashboard.load_jobs(path)


def test_loopback_routes_host_check_and_read_only():
    monitor = dashboard.Monitor(Client(), "private-bucket", [JOB])
    server = dashboard.make_server(monitor, port=0)
    assert server.server_address[0] == "127.0.0.1"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 200
        assert response.getheader("Cache-Control") == "no-store"
        assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
        assert b"Ghidra monitor" in response.read()
        connection.request("GET", "/api/status")
        response = connection.getresponse()
        assert response.status == 200
        assert len(json.loads(response.read())["jobs"]) == 1
        connection.request("GET", "/api/status", headers={"Host": "attacker.example"})
        response = connection.getresponse()
        assert response.status == 403
        response.read()
        connection.request("GET", "/.env")
        response = connection.getresponse()
        assert response.status == 404
        response.read()
        connection.request("POST", "/api/start")
        response = connection.getresponse()
        assert response.status == 501
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_cli_dispatch_and_validation(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_load_project_environment", lambda: None)
    calls = []
    monkeypatch.setattr(dashboard, "serve_dashboard", lambda *args: calls.append(args))
    path = tmp_path / "registry.json"
    assert cli.main(["data", "ghidra-dashboard", "--registry", str(path)]) == 0
    assert calls == [(path, 8765, 60)]


@pytest.mark.parametrize("port,interval", [(0, 60), (8765, 0), (8765, 29)])
def test_invalid_server_options_fail_before_aws_access(tmp_path, port, interval):
    with pytest.raises(SorelError, match="Dashboard needs"):
        dashboard.serve_dashboard(tmp_path / "unused", port, interval)
