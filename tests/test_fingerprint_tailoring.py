"""Tests for fingerprint-driven detector tailoring.

Covers:
* the base64 (php://filter) leaked-file matcher,
* LFI adding php://filter wrappers only when PHP is fingerprinted, and
* command-injection payload reordering when a Windows stack is detected.
"""
import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from scanner.detectors.cmdi import CommandInjectionDetector
from scanner.detectors.lfi import LFIDetector
from scanner.models import CrawlResult, ScanContext
from scanner.payloads import CMDI_SLEEP_TEMPLATES, match_lfi_encoded
from scanner.request_engine import RequestEngine


# --- base64 leaked-file matcher ---------------------------------------------

def test_match_lfi_encoded_detects_passwd():
    enc = base64.b64encode(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:").decode()
    assert match_lfi_encoded(f"<pre>{enc}</pre>") == "root:x:0:0:"


def test_match_lfi_encoded_ignores_benign_base64():
    enc = base64.b64encode(b"this is just some ordinary page content, nothing leaked here at all").decode()
    assert match_lfi_encoded(enc) is None


# --- LFI php://filter tailoring ---------------------------------------------

def _php_filter_server():
    def body(q):
        v = (q.get("file") or [""])[0]
        if v.startswith("php://filter") and "resource=" in v and "passwd" in v:
            blob = base64.b64encode(b"root:x:0:0:root:/root:/bin/bash\n").decode()
            return f"<pre>{blob}</pre>"
        return "<html>home</html>"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body(q).encode())

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _ctx(url, technologies):
    return ScanContext(
        target_url=url,
        crawl=CrawlResult(urls=[url]),
        allow_external=False,
        respect_robots=True,
        authenticated=False,
        technologies=technologies,
    )


def test_lfi_php_filter_flagged_when_php_detected():
    srv, base = _php_filter_server()
    try:
        url = f"{base}/read?file=home"
        findings = LFIDetector().run(_ctx(url, ["PHP"]), RequestEngine(delay_seconds=0.0))
        assert any("php://filter" in f.vulnerability for f in findings)
    finally:
        srv.shutdown()


def test_lfi_php_filter_not_used_without_php():
    srv, base = _php_filter_server()
    try:
        url = f"{base}/read?file=home"
        # Server only discloses via php://filter; without PHP fingerprinted the
        # wrapper payloads are not sent, so nothing should be found.
        findings = LFIDetector().run(_ctx(url, []), RequestEngine(delay_seconds=0.0))
        assert not findings
    finally:
        srv.shutdown()


# --- command-injection OS ordering ------------------------------------------

def _cmdi_ctx(technologies):
    return ScanContext(
        target_url="http://x/",
        crawl=CrawlResult(),
        allow_external=False,
        respect_robots=True,
        authenticated=False,
        technologies=technologies,
    )


def test_cmdi_windows_templates_prioritized_when_windows_detected():
    templates = CommandInjectionDetector()._sleep_templates(_cmdi_ctx(["Microsoft IIS"]))
    assert "ping -n" in templates[0] or "timeout" in templates[0]


def test_cmdi_default_order_when_not_windows():
    templates = CommandInjectionDetector()._sleep_templates(_cmdi_ctx(["nginx"]))
    assert templates[0] == CMDI_SLEEP_TEMPLATES[0]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
