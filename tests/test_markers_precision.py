"""Precision tests for detector signatures (priority #3).

The old detectors matched bare substrings ("mysql", "localhost", "127.0.0.1"),
firing on any page that merely mentioned them. These tests lock in that benign
mentions do NOT match while real error/leak content still does.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from scanner.payloads import match_sql_error, match_lfi, match_ssrf_markers
from scanner.request_engine import RequestEngine
from scanner.detectors.ssrf import SSRFDetector
from scanner.detectors.lfi import LFIDetector
from scanner.models import CrawlResult, ScanContext


# --- SQL error signatures ---------------------------------------------------

@pytest.mark.parametrize("benign", [
    "Powered by MySQL 8.0",
    "We migrated our data to PostgreSQL last year.",
    "Check out our MySQL tutorial series!",
    "The Aurora-50000 engine is fast.",       # must not match \bora-\d
    "SQLite is a great embedded database.",
])
def test_sql_error_no_false_positive(benign):
    assert match_sql_error(benign) is None


@pytest.mark.parametrize("real", [
    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    "Warning: mysqli_query() expects parameter 1",
    "ORA-00933: SQL command not properly ended",
    "Unclosed quotation mark after the character string ''.",
    "SQLSTATE[42000]: Syntax error or access violation",
    "unrecognized token: \"'\"",
])
def test_sql_error_true_positive(real):
    assert match_sql_error(real) is not None


# --- LFI leaked-file signatures --------------------------------------------

@pytest.mark.parametrize("benign", [
    "Connect to localhost to run the app.",
    "The loopback address is 127.0.0.1 for testing.",
    "The root account manages permissions.",
])
def test_lfi_no_false_positive(benign):
    assert match_lfi(benign) is None


@pytest.mark.parametrize("real", [
    "127.0.0.1       localhost",                       # hosts file line
    "root:x:0:0:root:/root:/bin/bash",                 # /etc/passwd line
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "; for 16-bit app support",                        # win.ini
    "[fonts]",
])
def test_lfi_true_positive(real):
    assert match_lfi(real) is not None


# --- SSRF markers -----------------------------------------------------------

@pytest.mark.parametrize("benign", [
    "Open localhost:3000 in your browser.",
    "The service binds to 127.0.0.1 by default.",
])
def test_ssrf_no_false_positive(benign):
    assert match_ssrf_markers(benign) is None


def test_ssrf_metadata_is_strong():
    kind, _ = match_ssrf_markers("ami-id\niam/security-credentials/s3-role")
    assert kind == "metadata"


def test_ssrf_connection_error_is_weak():
    kind, _ = match_ssrf_markers("cURL error 7: Failed to connect: Connection refused")
    assert kind == "connection"


# --- Live baseline-absence: a page that always shows the string must not fire

def _server(handler_body):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(handler_body(q).encode())
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _ctx(url):
    return ScanContext(target_url=url, crawl=CrawlResult(urls=[url]), allow_external=False,
                       respect_robots=True, authenticated=False)


def test_ssrf_baseline_absence_suppresses_constant_marker():
    # Page ALWAYS contains "connection refused" regardless of input -> no finding.
    srv, base = _server(lambda q: "<html>status: connection refused (cache node)</html>")
    try:
        url = f"{base}/api?url=x"
        findings = SSRFDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert not [f for f in findings if "SSRF" in f.vulnerability and f.severity != "info"]
    finally:
        srv.shutdown()


def test_lfi_baseline_absence_suppresses_constant_marker():
    # Page always echoes a passwd-looking line -> baseline absence suppresses it.
    srv, base = _server(lambda q: "<pre>root:x:0:0:root:/root:/bin/bash</pre>")
    try:
        url = f"{base}/read?file=x"
        findings = LFIDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert not findings
    finally:
        srv.shutdown()


def test_lfi_detects_when_marker_introduced_by_payload():
    # Only returns passwd content when a traversal payload is present.
    def body(q):
        v = (q.get("file") or [""])[0]
        if ".." in v or "etc/passwd" in v:
            return "<pre>root:x:0:0:root:/root:/bin/bash</pre>"
        return "<html>home</html>"
    srv, base = _server(body)
    try:
        url = f"{base}/read?file=home"
        findings = LFIDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert any("Local File Inclusion" in f.vulnerability for f in findings)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
