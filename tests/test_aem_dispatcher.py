"""Tests for the AEM dispatcher-bypass / JCR content-disclosure detector.

The reported bypass relies on a *literal* double slash (``//content/...``).
Python's ``http.server`` collapses ``//`` to ``/`` while parsing the request
line, so it cannot faithfully emulate the vulnerable AEM/Sling behaviour — these
tests therefore use a **raw socket** server that inspects the exact request
target on the wire:

* the site root advertises AEM (``/etc.clientlibs/`` marker + a ``/content/...``
  link), so the detector engages;
* the canonical single-slash ``.json`` request is blocked (HTTP 403); but
* any request whose target literally starts with ``//`` slips past the emulated
  dispatcher filter and returns a raw JCR node.

This simultaneously exercises ``RequestEngine.get_raw_path``, which must preserve
the ``//`` that ``requests``/``urllib3`` would otherwise normalise away.

A non-AEM server confirms the detector stays silent (no false positives).
"""
import socket
import threading

from scanner.detectors.aem import AEMDispatcherDetector
from scanner.models import CrawlResult, ScanContext
from scanner.request_engine import RequestEngine

_AEM_HTML = (
    b"<html><head>"
    b"<link rel='stylesheet' href='/etc.clientlibs/mysite/clientlibs/site.css'>"
    b"</head><body><a href='/content/mysite/en/home.html'>home</a></body></html>"
)
_JCR_JSON = b'{"jcr:primaryType":"nt:unstructured","email":"g16863@att.com"}'
_PLAIN_HTML = b"<html><body>just a normal site</body></html>"


def _http(status: str, ctype: str, body: bytes) -> bytes:
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + body


class _RawServer:
    """Minimal HTTP/1.1 server that preserves the literal request target."""

    def __init__(self, aem: bool):
        self.aem = aem
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split(" ")
            target = parts[1] if len(parts) >= 2 else "/"
            conn.sendall(self._route(target))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _route(self, target: str) -> bytes:
        if target == "/" or target.startswith("/?"):
            body = _AEM_HTML if self.aem else _PLAIN_HTML
            return _http("200 OK", "text/html", body)
        if self.aem and target.startswith("//"):
            # Dispatcher bypass: literal double slash slips past the filter.
            return _http("200 OK", "application/json", _JCR_JSON)
        # Canonical single-slash content requests are correctly blocked.
        return _http("403 Forbidden", "text/html", b"<html>Forbidden</html>")

    def shutdown(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _engine() -> RequestEngine:
    # Corporate hosts often export HTTP(S)_PROXY globally; a proxy cannot reach
    # 127.0.0.1, so force requests-based calls to ignore environment proxies.
    eng = RequestEngine(delay_seconds=0.0)
    eng.session.trust_env = False
    eng.session.proxies = {}
    return eng


def _run(aem: bool):
    srv = _RawServer(aem)
    base = f"http://127.0.0.1:{srv.port}"
    try:
        ctx = ScanContext(
            target_url=base,
            crawl=CrawlResult(urls=[base + "/"]),
            allow_external=False,
            respect_robots=True,
            authenticated=False,
            aem_max_paths=6,
        )
        return AEMDispatcherDetector().run(ctx, _engine())
    finally:
        srv.shutdown()


def test_double_slash_bypass_is_flagged():
    findings = _run(aem=True)
    bypass = [f for f in findings if "AEM Dispatcher Bypass" in f.vulnerability]
    assert bypass, "expected an AEM dispatcher-bypass finding"
    f = bypass[0]
    assert f.severity == "high"
    assert f.confidence == "high"
    assert "//" in f.url  # the winning request used the double-slash bypass
    assert "jcr:primaryType" in f.evidence


def test_non_aem_site_is_silent():
    findings = _run(aem=False)
    assert findings == []


def test_operator_supplied_path_forces_probe():
    srv = _RawServer(aem=True)
    base = f"http://127.0.0.1:{srv.port}"
    try:
        ctx = ScanContext(
            target_url=base,
            crawl=CrawlResult(urls=[]),
            allow_external=False,
            respect_robots=True,
            authenticated=False,
            aem_content_paths=["/content/attbusiness/en/industries.json"],
            aem_max_paths=4,
        )
        findings = AEMDispatcherDetector().run(ctx, _engine())
    finally:
        srv.shutdown()
    assert any("AEM Dispatcher Bypass" in f.vulnerability for f in findings)


def test_raw_path_preserves_double_slash():
    # Direct RequestEngine.get_raw_path contract: the '//' must survive on wire.
    srv = _RawServer(aem=True)
    base = f"http://127.0.0.1:{srv.port}"
    try:
        resp = _engine().get_raw_path(base, "//content/x.1.json")
    finally:
        srv.shutdown()
    assert resp is not None
    assert resp.status_code == 200
    assert "jcr:primaryType" in resp.text
