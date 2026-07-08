"""Boolean-based blind SQLi detection tests.

Reproduces the real-world ICE `GetData` pattern (a TRUE boolean condition
returns status=SUCCESS, a FALSE one returns status=FAIL) that error/time-based
checks miss, and confirms a non-injectable endpoint is not flagged.
"""
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from scanner.detectors.sqli import SQLiDetector
from scanner.models import CrawlResult, ScanContext
from scanner.request_engine import RequestEngine

_SUCCESS = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<root><response status="SUCCESS" startrecord="1" fetchedrecords="0" '
    'totalrecords="0"><NewDataSet/></response></root>'
)
_FAIL = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<root><response status="FAIL">GetData failed due to an internal server error.</response></root>'
)

_NUM_CMP = re.compile(r"(\d+)\s*=\s*(\d+)")
_STR_CMP = re.compile(r"'(\w+)'\s*=\s*'(\w+)'")


def _evaluate(expr: str) -> bool:
    """Tiny boolean oracle: AND together every numeric/string equality found."""
    comparisons = [(a, b) for a, b in _NUM_CMP.findall(expr)]
    comparisons += [(a, b) for a, b in _STR_CMP.findall(expr)]
    if not comparisons:
        return False
    return all(a == b for a, b in comparisons)


def _ice_server(vulnerable: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            where = (parse_qs(urlparse(self.path).query).get("whereCondition") or [""])[0]
            if vulnerable:
                body = _SUCCESS if _evaluate(where) else _FAIL
            else:
                body = _SUCCESS  # constant response regardless of input
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(body.encode())

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _ctx(url):
    return ScanContext(
        target_url=url,
        crawl=CrawlResult(urls=[url]),
        allow_external=False,
        respect_robots=True,
        authenticated=False,
    )


def test_boolean_blind_sqli_flagged_on_success_fail_oracle():
    srv, base = _ice_server(vulnerable=True)
    try:
        url = f"{base}/Ice.svc/GetData?whereCondition=1%3D1"
        findings = SQLiDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        boolean = [f for f in findings if "Boolean-based Blind" in f.vulnerability]
        assert boolean and boolean[0].parameter == "whereCondition"
    finally:
        srv.shutdown()


def test_boolean_blind_sqli_not_flagged_on_constant_endpoint():
    srv, base = _ice_server(vulnerable=False)
    try:
        url = f"{base}/Ice.svc/GetData?whereCondition=1%3D1"
        findings = SQLiDetector().run(_ctx(url), RequestEngine(delay_seconds=0.0))
        assert not [f for f in findings if "Boolean-based Blind" in f.vulnerability]
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
