"""Integration tests for form-based time SQLi parity with the URL path.

Locks in priority-#2 fixes: form injection points use a median+MAD baseline and
the configured/dynamic threshold (not a hardcoded 2.2s single-sample delta), and
therefore (a) detect a genuinely delaying field and (b) do NOT false-positive on
a uniformly-slow endpoint. Sleeps are kept at ~1s for a fast test.
"""
import random
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from scanner.request_engine import RequestEngine
from scanner.detectors.sqli import SQLiDetector
from scanner.models import CrawlResult, FormDescriptor, FormField, ScanContext

_SLEEP_RE = re.compile(r"SLEEP\((\d+)\)|pg_sleep\((\d+)\)|RECEIVE_MESSAGE\('bbscan',(\d+)\)", re.I)
_TRUE_RE = re.compile(r"IF\(1=1|WHEN 1=1", re.I)
SLOW_S = 0.5  # per-request delay for the delaying branch (kept small for test speed)


def _make_handler(mode):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            params = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}
            delay = 0.0
            if mode == "always_slow":
                delay = SLOW_S
            else:  # "vulnerable": only the injected q field sleeps, 1s scaled down
                q = params.get("q", "")
                m = _SLEEP_RE.search(q)
                if m:
                    if any(t in q.upper() for t in ("IF(", "WHEN", "CASE")):
                        if _TRUE_RE.search(q):
                            delay = SLOW_S
                    else:
                        delay = SLOW_S
            time.sleep(delay + random.uniform(0, 0.03))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")

    return H


def _run(mode):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        form = FormDescriptor(
            page_url=base, action_url=f"{base}/x", method="POST",
            fields=[FormField(name="q"), FormField(name="safe")],
        )
        ctx = ScanContext(
            target_url=base, crawl=CrawlResult(urls=[], forms=[form]),
            allow_external=False, respect_robots=True, authenticated=False,
            sqli_time_threshold=0.3, sqli_baseline_samples=2, sqli_test_samples=2,
            sqli_max_payloads=1,  # 1 error + 1 time + 1 diff pair -> fast, unambiguous
        )
        findings = SQLiDetector().run(ctx, RequestEngine(delay_seconds=0.0))
        return findings, ctx
    finally:
        srv.shutdown()


def test_vulnerable_form_field_is_flagged():
    findings, ctx = _run("vulnerable")
    tb = [f for f in findings if "Time-based" in f.vulnerability]
    flagged = {f.parameter for f in tb}
    assert "q" in flagged            # delaying field detected
    assert "safe" not in flagged     # control field not flagged


def test_form_probe_artifacts_are_logged():
    _, ctx = _run("vulnerable")
    form_probes = [p for p in ctx.metadata.get("sqli_probe_artifacts", []) if p.get("target") == "form"]
    assert form_probes, "form timing probes should be recorded for report coverage"
    assert any(p.get("mode") == "baseline" for p in form_probes)


def test_uniformly_slow_endpoint_no_false_positive():
    findings, _ = _run("always_slow")
    tb = [f for f in findings if "Time-based" in f.vulnerability]
    assert not tb, f"constant-latency endpoint must not trip timing SQLi: {[f.evidence for f in tb]}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
