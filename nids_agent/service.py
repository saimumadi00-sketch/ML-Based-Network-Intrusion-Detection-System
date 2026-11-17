"""Long-running NIDS service: follow a flow source, process micro-batches, expose health and metrics.

    python app.py --serve --follow /opt/zeek/logs/current/conn.log --format zeek --metrics-port 9108
    zeek-cut ... | python app.py --serve --follow - --format zeek

Delivery is at-least-once: the file checkpoint (byte offset + inode) is saved only after a batch has
been processed, so a crash re-processes at most one batch. Events are de-duplicated by flow_id; alerts
for that batch may repeat. A batch that raises is written to logs/dead_letter.jsonl and skipped.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

from .engine import NIDSAgent
from .utils import append_jsonl, utc_now_iso, write_json
from .zeek import ConnLogParser

log = logging.getLogger("nids.service")


def _line_parser(fmt: str) -> Callable[[str], Optional[Dict[str, Any]]]:
    if fmt == "zeek":
        return ConnLogParser().parse_line

    def parse_jsonl(line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            log.warning("skipping malformed JSON line")
            return None
        return rec if isinstance(rec, dict) else None

    return parse_jsonl


class FollowFileSource:
    """`tail -F` for a log file, with a resumable checkpoint.

    Handles rotation (the path now points at a new inode: the old file is drained, then the new one is
    read from the start) and truncation (the file shrank: restart at 0). Only complete lines are consumed.
    """

    def __init__(self, path: str, fmt: str, checkpoint_path: Optional[str] = None, from_start: bool = False) -> None:
        self.path = path
        self.fmt = fmt
        self.checkpoint_path = checkpoint_path
        self.parse = _line_parser(fmt)
        self.fh = None
        self.inode: Optional[int] = None
        self.offset = 0  # byte offset after the last complete line read
        self._committed: Dict[str, Any] = {}
        self._open(initial=True, from_start=from_start)

    def _load_checkpoint(self) -> Dict[str, Any]:
        if not self.checkpoint_path or not os.path.exists(self.checkpoint_path):
            return {}
        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _open(self, initial: bool = False, from_start: bool = False) -> None:
        if not os.path.exists(self.path):
            self.fh, self.inode, self.offset = None, None, 0
            return
        self.fh = open(self.path, "rb")
        st = os.fstat(self.fh.fileno())
        self.inode = st.st_ino
        self.parse = _line_parser(self.fmt)
        start = 0
        if initial:
            cp = self._load_checkpoint()
            if cp.get("inode") == st.st_ino and 0 <= cp.get("offset", -1) <= st.st_size:
                start = cp["offset"]
                log.info("resuming %s at byte %d", self.path, start)
            elif not from_start:
                start = st.st_size  # like tail -f: only new flows
        if start > 0 and self.fmt == "zeek":
            self._prime_zeek_header()
        self.fh.seek(start)
        self.offset = start

    def _prime_zeek_header(self) -> None:
        """Re-read the '#' header so a resumed TSV parser knows the field layout."""
        self.fh.seek(0)
        for raw in self.fh:
            if not raw.startswith(b"#"):
                break
            self.parse(raw.decode("utf-8", errors="replace"))

    def read(self, max_flows: int) -> List[Dict[str, Any]]:
        if self.fh is None:
            self._open()
            if self.fh is None:
                return []
        flows: List[Dict[str, Any]] = []
        while len(flows) < max_flows:
            pos = self.fh.tell()
            raw = self.fh.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                self.fh.seek(pos)  # partial line still being written
                break
            self.offset = self.fh.tell()
            flow = self.parse(raw.decode("utf-8", errors="replace"))
            if flow is not None:
                flows.append(flow)
        if len(flows) < max_flows:
            self._check_rotation()
        return flows

    def _check_rotation(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return  # rotated away, new file not created yet; keep draining the old handle
        if st.st_ino != self.inode:
            log.info("%s rotated; switching to new file", self.path)
            self.fh.close()
            self._open()
        elif st.st_size < self.offset:
            log.info("%s truncated; restarting at 0", self.path)
            self.fh.seek(0)
            self.offset = 0
            self.parse = _line_parser(self.fmt)

    def lag_bytes(self) -> int:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return 0
        return max(st.st_size - self.offset, 0) if st.st_ino == self.inode else st.st_size

    def commit(self) -> None:
        if not self.checkpoint_path or self.inode is None:
            return
        state = {"path": self.path, "inode": self.inode, "offset": self.offset, "updated": utc_now_iso()}
        if state["offset"] != self._committed.get("offset") or state["inode"] != self._committed.get("inode"):
            write_json(self.checkpoint_path, state)
            self._committed = state

    def close(self) -> None:
        if self.fh:
            self.fh.close()


class StdinSource:
    """Reads lines from stdin on a background thread so batches can still be flushed on a timer."""

    def __init__(self, fmt: str) -> None:
        self.parse = _line_parser(fmt)
        self.q: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=100_000)
        self.eof = False
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in sys.stdin:
            self.q.put(line)
        self.q.put(None)

    def read(self, max_flows: int) -> List[Dict[str, Any]]:
        flows: List[Dict[str, Any]] = []
        while len(flows) < max_flows:
            try:
                line = self.q.get_nowait()
            except queue.Empty:
                break
            if line is None:
                self.eof = True
                break
            flow = self.parse(line)
            if flow is not None:
                flows.append(flow)
        return flows

    def lag_bytes(self) -> int:
        return self.q.qsize()

    def commit(self) -> None:
        pass

    def close(self) -> None:
        pass


@dataclass
class Stats:
    started: float = field(default_factory=time.time)
    flows_total: int = 0
    batches_total: int = 0
    batch_errors_total: int = 0
    alerts_total: Dict[str, int] = field(default_factory=dict)
    last_batch_time: float = 0.0
    last_batch_seconds: float = 0.0
    last_batch_size: int = 0
    consecutive_errors: int = 0
    lag: int = 0
    model_version: str = "unknown"


class NIDSService:
    def __init__(self, agent: NIDSAgent, source: Any, batch_size: int = 500, max_wait: float = 2.0,
                 poll_interval: float = 0.25, metrics_port: Optional[int] = None,
                 metrics_host: str = "127.0.0.1", print_alerts: bool = False) -> None:
        self.agent = agent
        self.source = source
        self.batch_size = batch_size
        self.max_wait = max_wait
        self.poll_interval = poll_interval
        self.print_alerts = print_alerts
        self.stats = Stats()
        self.stop_event = threading.Event()
        self.dead_letter_path = os.path.join(agent.config.logs_dir, "dead_letter.jsonl")
        self._server: Optional[ThreadingHTTPServer] = None
        if metrics_port is not None:
            self._start_http(metrics_host, metrics_port)

    # ---- main loop -------------------------------------------------------------------------
    def run(self) -> None:
        buffer: List[Dict[str, Any]] = []
        first_at = 0.0
        while not self.stop_event.is_set():
            new = self.source.read(self.batch_size - len(buffer))
            if new and not buffer:
                first_at = time.monotonic()
            buffer.extend(new)
            self.stats.lag = self.source.lag_bytes()
            due = buffer and (len(buffer) >= self.batch_size or time.monotonic() - first_at >= self.max_wait)
            if due:
                self._process(buffer)
                buffer = []
            elif getattr(self.source, "eof", False) and not buffer:
                break
            elif not new:
                self.stop_event.wait(self.poll_interval)
        if buffer:
            self._process(buffer)  # graceful shutdown: finish what was read
        self.source.close()
        if self._server:
            self._server.shutdown()
        log.info("stopped after %d flows in %d batches", self.stats.flows_total, self.stats.batches_total)

    def _process(self, flows: List[Dict[str, Any]]) -> None:
        t0 = time.monotonic()
        try:
            alerts = self.agent.process_batch(flows)
        except Exception as exc:  # keep the service alive; park the batch for inspection
            self.stats.batch_errors_total += 1
            self.stats.consecutive_errors += 1
            log.exception("batch of %d flows failed; written to dead letter", len(flows))
            for flow in flows:
                append_jsonl(self.dead_letter_path, {"timestamp": utc_now_iso(), "error": repr(exc), "flow": flow})
        else:
            self.stats.consecutive_errors = 0
            for alert in alerts:
                sev = alert.split("SEVERITY:", 1)[1].split("]", 1)[0].strip() if "SEVERITY:" in alert else "UNKNOWN"
                self.stats.alerts_total[sev] = self.stats.alerts_total.get(sev, 0) + 1
                if self.print_alerts and "INFO —" not in alert:
                    print(alert, flush=True)
            log.info("batch: %d flows, %d alerts, %.3fs", len(flows), len(alerts), time.monotonic() - t0)
        # Checkpoint after the batch is handled (processed or dead-lettered): at-least-once delivery.
        self.source.commit()
        self.stats.flows_total += len(flows)
        self.stats.batches_total += 1
        self.stats.last_batch_size = len(flows)
        self.stats.last_batch_seconds = time.monotonic() - t0
        self.stats.last_batch_time = time.time()

    def stop(self, *_: Any) -> None:
        self.stop_event.set()

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

    # ---- health and metrics ----------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        s = self.stats
        healthy = s.consecutive_errors < 3
        return {
            "status": "ok" if healthy else "failing",
            "uptime_s": round(time.time() - s.started, 1),
            "flows_total": s.flows_total,
            "last_batch_age_s": round(time.time() - s.last_batch_time, 1) if s.last_batch_time else None,
            "consecutive_batch_errors": s.consecutive_errors,
            "source_lag": s.lag,
        }

    def prometheus(self) -> str:
        s = self.stats
        lines = [
            "# HELP nids_flows_total Flows processed.", "# TYPE nids_flows_total counter",
            f"nids_flows_total {s.flows_total}",
            "# HELP nids_batches_total Batches processed.", "# TYPE nids_batches_total counter",
            f"nids_batches_total {s.batches_total}",
            "# HELP nids_batch_errors_total Batches that failed and went to the dead letter file.",
            "# TYPE nids_batch_errors_total counter", f"nids_batch_errors_total {s.batch_errors_total}",
            "# HELP nids_alerts_total Alerts emitted, by severity.", "# TYPE nids_alerts_total counter",
        ]
        for sev, n in sorted(s.alerts_total.items()):
            lines.append(f'nids_alerts_total{{severity="{sev}"}} {n}')
        lines += [
            "# HELP nids_last_batch_seconds Processing time of the last batch.", "# TYPE nids_last_batch_seconds gauge",
            f"nids_last_batch_seconds {s.last_batch_seconds:.6f}",
            "# HELP nids_last_batch_timestamp_seconds Unix time the last batch finished.",
            "# TYPE nids_last_batch_timestamp_seconds gauge", f"nids_last_batch_timestamp_seconds {s.last_batch_time:.3f}",
            "# HELP nids_source_lag Unread bytes (file) or queued lines (stdin).", "# TYPE nids_source_lag gauge",
            f"nids_source_lag {s.lag}",
            "# HELP nids_up 1 while the service is healthy.", "# TYPE nids_up gauge",
            f"nids_up {1 if s.consecutive_errors < 3 else 0}",
        ]
        return "\n".join(lines) + "\n"

    def _start_http(self, host: str, port: int) -> None:
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/healthz":
                    h = service.health()
                    body, ctype, code = json.dumps(h).encode(), "application/json", 200 if h["status"] == "ok" else 503
                elif self.path == "/metrics":
                    body, ctype, code = service.prometheus().encode(), "text/plain; version=0.0.4", 200
                else:
                    body, ctype, code = b"not found\n", "text/plain", 404
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: Any) -> None:
                pass

        self._server = ThreadingHTTPServer((host, port), Handler)
        self.metrics_port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        log.info("health/metrics on http://%s:%d/healthz and /metrics", host, self.metrics_port)
