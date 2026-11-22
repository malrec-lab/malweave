"""Loopback-only, read-only aggregate monitor for private Ghidra S3 reports."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
import time

from malweave.data.sorel import SorelError

MAX_REPORT_BYTES = 64 * 1024**2


@dataclass(frozen=True)
class Job:
    account: str
    name: str
    report_key: str
    slug: str
    historical: bool = False


def load_jobs(path: Path) -> list[Job]:
    """Read an explicit local registry; never discover inventories or sample objects."""
    try:
        entries = json.loads(path.read_text())["jobs"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
            raise ValueError
        jobs = []
        seen = set()
        for entry in entries:
            job = Job(**entry)
            if (
                not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", job.account)
                or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", job.slug)
                or not re.fullmatch(r"[a-zA-Z0-9 _-]{1,80}", job.name)
                or not isinstance(job.historical, bool)
                or not re.fullmatch(
                    r"analysis/private-batches/[a-zA-Z0-9_/-]+/benchmark-report\.json",
                    job.report_key,
                )
                or ".." in job.report_key
                or job.report_key in seen
                or (job.account, job.slug) in {(j.account, j.slug) for j in jobs}
            ):
                raise ValueError
            seen.add(job.report_key)
            jobs.append(job)
        return jobs
    except (KeyError, TypeError, ValueError) as error:
        raise SorelError(
            "Invalid dashboard registry; expected unique job/report mappings."
        ) from error


def _count(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Invalid report count.")
    return value


def load_pool(path: Path) -> tuple[str, int] | None:
    """An optional explicit denominator, not inferred from queued attempt sizes."""
    try:
        pool = json.loads(path.read_text()).get("pool")
        if pool is None:
            return None
        name, total = pool["name"], _count(pool["total"])
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9 _-]{1,80}", name):
            raise ValueError
        if not total:
            raise ValueError
        return name, total
    except (KeyError, TypeError, ValueError) as error:
        raise SorelError("Invalid dashboard pool; expected a name and positive total.") from error


def load_pool_members(path: Path) -> set[str] | None:
    """Load an explicitly pinned private cohort; never expose identities in HTTP."""
    specification = json.loads(path.read_text()).get("pool", {})
    filename = specification.get("members_path")
    if filename is None:
        return None
    payload = Path(filename).read_bytes()
    from hashlib import sha256

    if sha256(payload).hexdigest() != specification.get("members_sha256"):
        raise SorelError("Dashboard pool membership digest mismatch.")
    members = json.loads(payload)
    if (
        not isinstance(members, list)
        or any(not isinstance(s, str) or not re.fullmatch(r"[0-9a-f]{64}", s) for s in members)
        or len(set(members)) != len(members)
        or len(members) != specification["total"]
    ):
        raise SorelError("Invalid dashboard pool membership.")
    return set(members)


def source_coverage(report: dict) -> dict:
    """Keep source identities in backend memory only for cross-attempt deduplication."""
    coverage = {
        "done": set(),
        "dis": set(),
        "dec": set(),
        "pending": set(),
        "excluded": set(),
        "unknown_rows": 0,
    }
    for row in report["results"]:
        sha = row.get("source_sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            coverage["unknown_rows"] += 1
            continue
        if row.get("excluded"):
            coverage["excluded"].add(sha)
            continue
        if row.get("pending"):
            coverage["pending"].add(sha)
            continue
        coverage["done"].add(sha)
        for view in row.get("views", []):
            if view.get("view") in {"dis", "dec"} and view.get("status") == "success":
                coverage[view["view"]].add(sha)
    return coverage


def summarize_report(report: dict, modified: datetime, now: float) -> dict:
    """Allowlist aggregate fields: never return source IDs, logs, URLs or raw errors."""
    rows = report["results"]
    total = _count(report["source_count"])
    if not isinstance(rows, list) or len(rows) > total:
        raise ValueError("Invalid report results.")
    clean = dis = dec = published = no_success = deferred = excluded = 0
    for row in rows:
        if row.get("excluded"):
            excluded += 1
            continue
        if row.get("pending"):
            deferred += 1
            continue
        views = row.get("views", [])
        successful = {v["view"] for v in views if v["status"] == "success"}
        dis += "dis" in successful
        dec += "dec" in successful
        clean += len(views) == 2 and successful == {"dis", "dec"}
        no_success += not (successful & {"dis", "dec"})
        published += sum(
            v.get("view") in {"dis", "dec"}
            and v.get("status") == "success"
            and bool(v.get("representation_sha256"))
            for v in views
        )
    seconds = float(report.get("seconds", 0))
    rss = _count(report.get("resources", {}).get("sampled_process_tree_peak_rss_bytes", 0))
    if not 0 <= seconds < 365 * 86400:
        raise ValueError("Invalid report runtime.")
    status = report["status"]
    if status not in {"running", "completed", "completed_with_exclusions", "partial", "failed"}:
        status = "unknown"
    return {
        "reported_status": status,
        "report_modified": modified.timestamp(),
        "fetched_at": now,
        "total": total,
        "workers": _count(report["workers"]) if "workers" in report else None,
        "done": len(rows),
        "clean": clean,
        "partial_failed": len(rows) - clean - deferred - excluded,
        "excluded_dotnet": excluded,
        "deferred_pending": deferred,
        "no_success": no_success,
        "dis_success": dis,
        "dec_success": dec,
        "published_views": published,
        "dis_checkpointed": sum(
            "dis" in v.get("published_views", []) for v in report.get("inflight", {}).values()
        ),
        "seconds": seconds,
        "peak_process_rss_gib": round(rss / 1024**3, 1),
        "coordinator_error": bool(report.get("coordinator_error_type")),
    }


class Monitor:
    """Fetch on a fixed background cadence, not on browser requests."""

    def __init__(
        self,
        client,
        bucket: str,
        jobs: list[Job],
        interval: int = 60,
        pool=None,
        pool_members=None,
    ):
        self.client, self.bucket, self.jobs, self.interval = client, bucket, jobs, interval
        self.history_interval = max(900, interval)
        self.pool = pool
        self.pool_members = pool_members
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.records: dict[str, dict] = {}
        self.round_finished: float | None = None
        self.refreshing = False

    def _fetch(self, job: Job) -> None:
        with self.lock:
            old = self.records.get(job.report_key, {})
        try:
            options = {"Bucket": self.bucket, "Key": job.report_key}
            if old.get("etag"):
                options["IfNoneMatch"] = old["etag"]
            response = self.client.get_object(**options)
            with response["Body"] as body:
                payload = body.read(MAX_REPORT_BYTES + 1)
            if len(payload) > MAX_REPORT_BYTES:
                raise ValueError("Report exceeds monitor limit.")
            report = json.loads(payload)
            summary = summarize_report(report, response["LastModified"], time.time())
            record = {
                "summary": summary,
                "coverage": source_coverage(report),
                "etag": response.get("ETag"),
                "fetch_error": None,
            }
        except Exception as error:  # noqa: BLE001 -- sanitize SDK/report failures at the UI boundary.
            # SDK exceptions may contain private endpoints/keys. Do not expose or log them.
            response = getattr(error, "response", None) or {}
            unchanged = response.get("ResponseMetadata", {}).get(
                "HTTPStatusCode"
            ) == 304 or response.get("Error", {}).get("Code") in {"304", "NotModified"}
            if unchanged and old.get("summary") and old.get("etag"):
                # Conditional S3 GET confirmed the same object, not a failed read.
                record = {
                    **old,
                    "summary": {**old["summary"], "fetched_at": time.time()},
                    "fetch_error": None,
                }
            else:
                record = {**old, "fetch_error": "Không đọc được report"}
        with self.lock:
            self.records[job.report_key] = record

    def refresh(self, jobs: list[Job] | None = None, *, mark_round: bool = True) -> None:
        jobs = self.jobs if jobs is None else jobs
        if mark_round:
            with self.lock:
                self.refreshing = True
        try:
            if jobs:
                with ThreadPoolExecutor(
                    max_workers=min(5 if mark_round else 2, len(jobs))
                ) as pool:
                    list(pool.map(self._fetch, jobs))
        finally:
            if mark_round:
                with self.lock:
                    self.round_finished = time.time()
                    self.refreshing = False

    def _history_loop(self) -> None:
        historical = [job for job in self.jobs if job.historical]
        while not self.stop.is_set() and historical:
            self.refresh(historical, mark_round=False)
            if self.stop.wait(self.history_interval):
                break

    def run(self) -> None:
        # Old, log-heavy reports cannot block the current-job polling pool.
        history = threading.Thread(target=self._history_loop, daemon=True)
        history.start()
        current = [job for job in self.jobs if not job.historical]
        try:
            while not self.stop.is_set():
                self.refresh(current)
                if self.stop.wait(self.interval):
                    break
        finally:
            self.stop.set()
            history.join(timeout=2)

    def snapshot(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self.lock:
            records = dict(self.records)
            finished = self.round_finished
            refreshing = self.refreshing
        rows = []
        for job in self.jobs:
            record = records.get(job.report_key, {})
            summary = record.get("summary")
            row = {
                "account": job.account,
                "name": job.name,
                "historical": job.historical,
                "notebook_url": f"https://www.kaggle.com/code/{job.account}/{job.slug}",
                "fetch_error": record.get("fetch_error"),
                "state": "waiting",
            }
            if summary:
                row.update(summary)
                age = max(0, now - summary["report_modified"])
                row["heartbeat_age_s"] = round(age)
                row["fetch_age_s"] = round(max(0, now - summary["fetched_at"]))
                expected_interval = self.history_interval if job.historical else self.interval
                if record.get("fetch_error"):
                    row["state"] = "unavailable"
                elif row["fetch_age_s"] > expected_interval * 3:
                    row["state"] = "cache_stale"
                elif row["reported_status"] == "running":
                    row["state"] = "fresh" if age <= 180 else "stale"
                else:
                    row["state"] = row["reported_status"]
            elif record.get("fetch_error"):
                row["state"] = "unavailable"
            rows.append(row)
        pool = None
        if self.pool:
            done, dis, dec, pending, excluded = set(), set(), set(), set(), set()
            unknown_rows = 0
            for record in records.values():
                coverage = record.get("coverage", {})
                done.update(coverage.get("done", set()))
                dis.update(coverage.get("dis", set()))
                dec.update(coverage.get("dec", set()))
                pending.update(coverage.get("pending", set()))
                excluded.update(coverage.get("excluded", set()))
                unknown_rows += coverage.get("unknown_rows", 0)
            done -= excluded
            dis -= excluded
            dec -= excluded
            if self.pool_members is not None:
                done &= self.pool_members
                dis &= self.pool_members
                dec &= self.pool_members
                pending &= self.pool_members
                excluded &= self.pool_members
            pool = {
                "name": self.pool[0],
                "total": self.pool[1],
                "done": len(done),
                "both_success": len(dis & dec),
                "partial_failed_only": len(done - (dis & dec)),
                "remaining": max(0, self.pool[1] - len(done | excluded)),
                "excluded_dotnet": len(excluded),
                "deferred_pending": len(pending - done),
                "reports_loaded": sum(bool(r.get("coverage")) for r in records.values()),
                "registered_reports": len(self.jobs),
                "unavailable_reports": sum(
                    r["state"] in {"unavailable", "cache_stale"} for r in rows
                ),
                "unknown_identity_rows": unknown_rows,
                "denominator_exceeded": len(done) > self.pool[1],
            }
        return {
            "now": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "refresh_seconds": self.interval,
            "history_refresh_seconds": self.history_interval,
            "refresh_in_progress": refreshing,
            "last_round_finished": finished,
            "jobs": rows,
            "pool": pool,
        }


PAGE = """<!doctype html>
<html lang="vi"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MalWeave · Ghidra monitor</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101722;color:#e6edf6}
body{max-width:1450px;margin:auto;padding:26px}h1{margin-bottom:5px;font-size:26px}
p,.muted{color:#a7b8cf}header{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:22px 0}.card,section{background:#192434;
border:1px solid #304159;border-radius:12px;padding:18px}.card{min-width:150px}
.card b{font-size:26px;display:block}.card span{color:#b1c1d7;font-size:13px}
section{margin:20px 0;overflow:auto}h2{font-size:20px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;white-space:nowrap;font-size:14px}
td,th{text-align:left;padding:12px 9px;border-bottom:1px solid #304159}
th{color:#b1c1d7;font-size:12px}a{color:#8ec6ff}progress{width:95px;accent-color:#72c5f5}
.badge{border-radius:6px;padding:4px 8px;background:#29374d;font-size:12px}
.fresh,.completed{color:#8ce3b0}.stale,.partial,.cache_stale{color:#ffd18c}
.unavailable,.failed{color:#ffaaaa}.controls{display:flex;gap:18px;align-items:center}
select,button{background:#223149;color:#e6edf6;border:1px solid #52647d;
padding:7px;border-radius:6px}footer{font-size:13px;line-height:1.7}
</style>
<header><div><h1>MalWeave · Ghidra monitor</h1>
<p>Chỉ xem · S3 → localhost · không cần đổi account Kaggle</p></div>
<div id="clock" class="muted">Đang kết nối…</div></header>
<div id="pool"></div>
<div class="controls"><label>Account <select id="account"><option value="">Tất cả</option>
</select></label><label><input id="history" type="checkbox"> Hiện lượt cũ</label></div>
<div id="cards" class="cards"></div><div id="groups"></div>
<footer class="muted">
“Heartbeat mới” chỉ xác nhận coordinator ghi report, không xác nhận parser không bị kẹt.
“Mất cập nhật” không phải xác nhận Kaggle đã dừng.<br>
DIS/DEC thành công là trạng thái parser, không bảo đảm chất lượng nội dung.
Partial không đồng nghĩa phải loại mẫu. View đã lưu là số receipt trong report, không HEAD lại S3.<br>
DIS checkpoint là nguồn chưa chốt kết quả cuối nhưng đã lưu checkpoint DIS.
RSS là đỉnh tổng RSS cây tiến trình, có thể đếm trùng bộ nhớ; không phải RAM cgroup hay bằng chứng OOM.<br>
Tổng theo account đếm lượt xử lý đang hiển thị, không phải số nguồn duy nhất toàn corpus.
Thời gian chạy là mốc của report, không tự cộng khi heartbeat mất.
Không có chức năng start/stop job; không tải mẫu gốc.
</footer>
<script>
let latest=null;
const $=id=>document.getElementById(id);
const fmt=n=>n==null?'—':Number(n).toLocaleString('vi-VN');
const dur=s=>s==null?'—':s<60?Math.round(s)+'s':
 s<3600?Math.floor(s/60)+'m '+Math.round(s%60)+'s':
 Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m';
const labels={waiting:'Đang đọc lần đầu',fresh:'Heartbeat mới',stale:'Mất cập nhật',
 unavailable:'Lỗi đọc S3',cache_stale:'Dashboard cập nhật chậm',
 completed:'Đã kết thúc',completed_with_exclusions:'Kết thúc · có loại .NET',partial:'Kết thúc · có partial',
 failed:'Report báo lỗi',unknown:'Không rõ'};
function el(tag,text,cls){const e=document.createElement(tag);
 if(text!=null)e.textContent=text;if(cls)e.className=cls;return e;}
function render(){
 if(!latest)return;
 $('pool').replaceChildren();
 const p=latest.pool;
 if(p){
 const section=el('section'),cards=el('div',null,'cards');
 section.append(el('h2','Tiến độ toàn '+p.name+' · nguồn duy nhất'));
 const percent=(100*p.done/p.total).toLocaleString('vi-VN',{maximumFractionDigits:2});
 for(const [title,value] of [
 ['Có kết quả cuối (gồm partial/lỗi)',fmt(p.done)+' / '+fmt(p.total)+' · '+percent+'%'],
 ['Đủ DIS + DEC thành công',fmt(p.both_success)],
 ['Có kết quả nhưng chưa đủ DIS + DEC OK',fmt(p.partial_failed_only)],
 ['Chưa có kết quả cuối trong report',fmt(p.remaining)]]){
 const card=el('div',null,'card');card.append(el('b',value),el('span',title));cards.append(card);}
 section.append(cards);
 const bar=el('progress');bar.max=p.total;bar.value=p.done;bar.style.width='100%';
 section.append(bar);
 section.append(el('p','Khử trùng theo source SHA-256 ở backend, gồm cả lượt cũ; không đổi khi lọc account. '+
 'Theo '+p.reports_loaded+'/'+p.registered_reports+' report đã đọc. '+
 'Không tính checkpoint chưa có kết quả cuối trong report. Không phải audit toàn kho S3.'));
 if(p.unavailable_reports||p.unknown_identity_rows||p.reports_loaded<p.registered_reports||
 p.denominator_exceeded)section.append(el('p',
 'Số liệu chưa đầy đủ hoặc cần kiểm tra: report thiếu/cache lỗi, nguồn thiếu định danh hoặc vượt tổng pool.',
 'stale'));
 $('pool').append(section);
 }
 const selected=$('account').value,history=$('history').checked;
 const rows=latest.jobs.filter(j=>(!selected||j.account===selected)&&(history||!j.historical));
 $('cards').replaceChildren();
 for(const [title,value] of [['Job',rows.length],
 ['Có kết quả / lượt đã đọc',rows.some(j=>j.total!=null)?
 fmt(rows.reduce((s,j)=>s+(j.done||0),0))+' / '+fmt(rows.reduce((s,j)=>s+(j.total||0),0)):'—'],
 ['DIS + DEC thành công',fmt(rows.reduce((s,j)=>s+(j.clean||0),0))],
  ['Partial / failed',fmt(rows.reduce((s,j)=>s+(j.partial_failed||0),0))],
  ['Đợi backend / kiểm tra PE',fmt(rows.reduce((s,j)=>s+(j.deferred_pending||0),0))],
  ['.NET đã loại',fmt(rows.reduce((s,j)=>s+(j.excluded_dotnet||0),0))],
 ['View đã lưu',fmt(rows.reduce((s,j)=>s+(j.published_views||0),0))]]){
 const card=el('div',null,'card');card.append(el('b',value),el('span',title));
 $('cards').append(card);}
 $('groups').replaceChildren();
 for(const account of [...new Set(rows.map(j=>j.account))]){
 const group=rows.filter(j=>j.account===account),section=el('section');
 section.append(el('h2',account+' · '+group.length+' job'));
 const table=el('table'),head=el('tr');
 for(const t of ['Job','Report','Worker tối đa','Có bản ghi','DIS+DEC OK','Partial/lỗi','Đợi backend/review','.NET đã loại','DIS OK / DEC OK',
 'DIS checkpoint','View lưu','Thời gian','Heartbeat','RSS đỉnh'])head.append(el('th',t));
 table.append(head);
 for(const j of group){
 const tr=el('tr'),link=el('a',j.name+(j.historical?' · lượt cũ':''));
 link.href=j.notebook_url;link.target='_blank';link.rel='noopener noreferrer';
 const name=el('td');name.append(link);tr.append(name);
 const state=el('td');state.append(el('span',labels[j.state]||'Không rõ','badge '+j.state));
 if(j.coordinator_error)state.append(el('span',' · coordinator lỗi','failed'));
 tr.append(state);
 tr.append(el('td',fmt(j.workers)));
 const count=el('td',j.total==null?'—':fmt(j.done)+' / '+fmt(j.total)+' ');
 if(j.total){const bar=el('progress');bar.max=j.total;bar.value=j.done;count.append(bar);}
 tr.append(count);
 for(const v of [fmt(j.clean),fmt(j.partial_failed),fmt(j.deferred_pending),fmt(j.excluded_dotnet),
 j.total==null?'—':fmt(j.dis_success)+' / '+fmt(j.dec_success),
 fmt(j.dis_checkpointed),fmt(j.published_views),dur(j.seconds),dur(j.heartbeat_age_s),
 j.peak_process_rss_gib==null?'—':j.peak_process_rss_gib+' GiB'])tr.append(el('td',v));
 table.append(tr);}
 section.append(table);$('groups').append(section);}
}
async function poll(){
 try{
 const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw Error('HTTP');
 latest=await r.json();
 const selected=$('account').value;
 const accounts=[...new Set(latest.jobs.map(j=>j.account))];
 $('account').replaceChildren(new Option('Tất cả',''),...accounts.map(a=>new Option(a,a)));
 $('account').value=selected;
 const last=latest.last_round_finished;
 $('clock').textContent='Job hiện tại: '+latest.refresh_seconds+'s · Lượt cũ: '+
 Math.round(latest.history_refresh_seconds/60)+' phút · '+
 (latest.refresh_in_progress?'Đang đọc S3 · ':'')+
 (last?'Lượt đọc xong '+new Date(last*1000).toLocaleTimeString('vi-VN'):
 'Đang đọc S3 lần đầu…');
 render();
 }catch(e){$('clock').textContent='Mất kết nối localhost — dữ liệu bên dưới là cache cũ';}
}
$('account').onchange=render;$('history').onchange=render;
poll();setInterval(poll,5000);
</script></html>"""


def make_server(monitor: Monitor, port: int = 8765) -> ThreadingHTTPServer:
    """Expose only two allowlisted GET routes; reject non-loopback Host headers."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            expected = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") not in {
                expected,
                expected.replace("127.0.0.1", "localhost"),
            }:
                self.send_error(403)
                return
            if self.path == "/":
                content, mime = PAGE.encode(), "text/html; charset=utf-8"
            elif self.path == "/api/status":
                content = json.dumps(monitor.snapshot(), ensure_ascii=False).encode()
                mime = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve_dashboard(registry: Path, port: int = 8765, interval: int = 60) -> None:
    """Create the AWS client only on explicit CLI execution; no writes to S3."""
    if not 1 <= port <= 65535 or not 30 <= interval <= 3600:
        raise SorelError("Dashboard needs port 1..65535 and refresh interval 30..3600 seconds.")
    jobs = load_jobs(registry)
    pool = load_pool(registry)
    bucket = os.environ.get("MALWEAVE_RANDS_S3_BUCKET")
    if not bucket:
        raise SorelError("Set MALWEAVE_RANDS_S3_BUCKET in the local environment or .env.")
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "s3",
        region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        config=Config(
            connect_timeout=5,
            read_timeout=20,
            retries={"total_max_attempts": 2},
            max_pool_connections=7,
        ),
    )
    monitor = Monitor(
        client, bucket, jobs, interval, pool=pool, pool_members=load_pool_members(registry)
    )
    server = make_server(monitor, port)
    thread = threading.Thread(target=monitor.run, daemon=True)
    thread.start()
    print(f"Ghidra dashboard: http://127.0.0.1:{port} ({len(jobs)} registered jobs)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Dashboard stopped; remote jobs unchanged.", flush=True)
    finally:
        monitor.stop.set()
        server.server_close()
        thread.join(timeout=2)
