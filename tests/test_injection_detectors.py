"""Integration tests for the SSTI, command-injection, and XXE detectors.

Each test spins up a throwaway HTTP server that emulates the vulnerable
behaviour (template evaluation / shell delay / XML entity resolution) and a
safe control, locking in both true-positive detection and false-positive
suppression. Sleeps are kept small for speed.
"""
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from scanner.detectors.cmdi import CommandInjectionDetector
from scanner.detectors.ssti import SSTIDetector
from scanner.detectors.xxe import XXEDetector
from scanner.models import CrawlResult, FormDescriptor, PageObservation, ScanContext
from scanner.request_engine import RequestEngine

_MULT_RE = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")
_SLEEP_RE = re.compile(r"sleep\s+(\d+)", re.I)
_PING_RE = re.compile(r"ping\s+-n\s+(\d+)", re.I)
SLOW_S = 0.6


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _ctx(url, **kw):
    return ScanContext(
        target_url=url,
        crawl=kw.pop("crawl", CrawlResult(urls=[url])),
        allow_external=False,
        respect_robots=True,
        authenticated=False,
        **kw,
    )


# --- SSTI --------------------------------------------------------------------

def _ssti_server(evaluate):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
            rendered = _MULT_RE.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), value) if evaluate else value
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html>{rendered}</html>".encode())

    return _serve(H)


def test_ssti_evaluated_expression_is_flagged():
    srv, base = _ssti_server(evaluate=True)
    try:
        url = f"{base}/page?name=x"
        findings = SSTIDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert any("Server-Side Template Injection" in f.vulnerability for f in findings)
    finally:
        srv.shutdown()


def test_ssti_reflected_only_is_not_flagged():
    srv, base = _ssti_server(evaluate=False)
    try:
        url = f"{base}/page?name=x"
        findings = SSTIDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert not findings
    finally:
        srv.shutdown()


# --- Command injection -------------------------------------------------------

def _cmdi_server(mode):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            value = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            delay = 0.0
            if mode == "always_slow":
                delay = SLOW_S
            else:  # "vulnerable": only a real (non-zero) sleep/ping payload delays
                sm = _SLEEP_RE.search(value)
                pm = _PING_RE.search(value)
                if sm and int(sm.group(1)) > 0:
                    delay = SLOW_S
                elif pm and int(pm.group(1)) > 1:
                    delay = SLOW_S
            time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")

    return _serve(H)


def _cmdi_ctx(url):
    return _ctx(url, cmdi_time_threshold=0.3, cmdi_baseline_samples=2, cmdi_test_samples=2, cmdi_max_payloads=1)


def test_cmdi_time_delay_is_flagged():
    srv, base = _cmdi_server("vulnerable")
    try:
        url = f"{base}/run?q=x"
        findings = CommandInjectionDetector().run(_cmdi_ctx(url), RequestEngine(delay_seconds=0.0))
        assert any("OS Command Injection" in f.vulnerability for f in findings)
    finally:
        srv.shutdown()


def test_cmdi_uniformly_slow_endpoint_no_false_positive():
    srv, base = _cmdi_server("always_slow")
    try:
        url = f"{base}/run?q=x"
        findings = CommandInjectionDetector().run(_cmdi_ctx(url), RequestEngine(delay_seconds=0.0))
        assert not [f for f in findings if "OS Command Injection" in f.vulnerability]
    finally:
        srv.shutdown()


# --- XXE ---------------------------------------------------------------------

def _xxe_server(vulnerable):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode(errors="ignore")
            out = "<ok/>"
            if vulnerable and 'SYSTEM "file:///etc/passwd"' in body and "&xxe;" in body:
                out = "<data>root:x:0:0:root:/root:/bin/bash</data>"
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(out.encode())

    return _serve(H)


def test_xxe_inband_file_read_is_flagged():
    srv, base = _xxe_server(vulnerable=True)
    try:
        url = f"{base}/xml"
        findings = XXEDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert any("XXE" in f.vulnerability for f in findings)
    finally:
        srv.shutdown()


def test_xxe_non_resolving_parser_is_not_flagged():
    srv, base = _xxe_server(vulnerable=False)
    try:
        url = f"{base}/xml"
        findings = XXEDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert not [f for f in findings if f.severity != "info"]
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
