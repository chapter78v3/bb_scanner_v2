from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import Dict, Optional

import requests
from requests.structures import CaseInsensitiveDict


def _silence_insecure_warnings() -> None:
    """Suppress urllib3's InsecureRequestWarning on every urllib3 in play.

    The warning is emitted by whichever urllib3 actually issues the request —
    the standalone ``urllib3`` package and/or the copy vendored inside
    ``requests`` — so disable it on both, and add a ``warnings`` filter as a
    belt-and-braces fallback. Called once when a TLS-unverified engine is built.
    """
    try:
        import urllib3
        from urllib3.exceptions import InsecureRequestWarning

        urllib3.disable_warnings(InsecureRequestWarning)
        import warnings

        warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    except Exception:
        pass
    try:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
    except Exception:
        pass



class RawResponse:
    """Lightweight response for :meth:`RequestEngine.get_raw_path`.

    Exposes the subset of the ``requests.Response`` API that detectors rely on
    (``status_code``, case-insensitive ``headers``, ``text``, ``url``) without
    pulling in urllib3's URL normalisation.
    """

    __slots__ = ("status_code", "headers", "text", "url")

    def __init__(self, status_code: int, headers: CaseInsensitiveDict, text: str, url: str) -> None:
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.url = url



class RequestEngine:
    """HTTP request wrapper with session state, throttling, retries, and proxy support."""

    def __init__(
        self,
        delay_seconds: float = 0.2,
        timeout_seconds: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
    ) -> None:
        self.delay_seconds = max(0.0, delay_seconds)
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self.verify_tls = verify_tls
        if not verify_tls:
            # When the operator opts out of TLS verification (e.g. behind a
            # TLS-intercepting corporate proxy), silence urllib3's per-request
            # InsecureRequestWarning so it does not flood the scan output.
            _silence_insecure_warnings()
        self.max_retries = max(0, max_retries)
        self.backoff_factor = max(0.0, backoff_factor)
        self._last_request_ts = 0.0
        self._throttle_lock = threading.Lock()

    def _throttle(self) -> None:
        # Global, thread-safe rate limit: serialize the wait so the configured
        # delay is honored even when many worker threads share this engine.
        with self._throttle_lock:
            elapsed = time.monotonic() - self._last_request_ts
            if elapsed < self.delay_seconds:
                time.sleep(self.delay_seconds - elapsed)
            self._last_request_ts = time.monotonic()

    @staticmethod
    def _retry_after_seconds(response: requests.Response, default: float) -> float:
        header = response.headers.get("Retry-After")
        if header:
            try:
                return max(0.0, float(header))
            except ValueError:
                return default
        return default

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout_seconds)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_tls)

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                response = self.session.request(method=method.upper(), url=url, **kwargs)
                self._last_request_ts = time.monotonic()
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                self._last_request_ts = time.monotonic()
                if attempt >= self.max_retries:
                    raise
                time.sleep(self.backoff_factor * (2 ** attempt))
                continue

            if response.status_code in (429, 503) and attempt < self.max_retries:
                wait = self._retry_after_seconds(response, self.backoff_factor * (2 ** attempt))
                time.sleep(wait)
                continue

            return response

        if last_exc is not None:
            raise last_exc
        raise requests.exceptions.RequestException("Request failed without a response")

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    # ------------------------------------------------------------------ #
    # Raw request-target support                                          #
    # ------------------------------------------------------------------ #
    def get_raw_path(
        self,
        base_url: str,
        raw_target: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[RawResponse]:
        """GET whose request-target is sent *verbatim*, preserving a literal ``//``.

        ``requests``/``urllib3`` normalise a leading ``//`` in the path to ``/``
        on the wire, which silently defeats dispatcher-bypass probes that depend
        on the duplicate slash (e.g. AEM ``//content/...``). This performs a
        minimal raw HTTP/1.1 exchange over a socket — with TLS and optional
        proxy support — so the exact target reaches the server, mirroring
        ``curl "https://host//content..."``. Returns ``None`` on any transport
        error (callers treat that as "no signal").
        """
        parsed = requests.utils.urlparse(base_url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)

        self._throttle()
        sock = None
        try:
            proxy_url = self._proxy_for(scheme, host)
            if proxy_url:
                p = requests.utils.urlparse(proxy_url)
                sock = socket.create_connection(
                    (p.hostname, p.port or 8080), timeout=self.timeout_seconds
                )
                if scheme == "https":
                    connect = (
                        f"CONNECT {host}:{port} HTTP/1.1\r\n"
                        f"Host: {host}:{port}\r\n\r\n"
                    )
                    sock.sendall(connect.encode("latin-1"))
                    status_line = self._read_headers(sock).split(b"\r\n", 1)[0]
                    if b" 200 " not in status_line and not status_line.endswith(b" 200"):
                        return None
                    sock = self._wrap_tls(sock, host)
                    request_target = raw_target
                else:
                    request_target = f"{scheme}://{host}:{port}{raw_target}"
            else:
                sock = socket.create_connection((host, port), timeout=self.timeout_seconds)
                if scheme == "https":
                    sock = self._wrap_tls(sock, host)
                request_target = raw_target

            header_block = self._raw_header_block(host, port, extra_headers)
            request = f"GET {request_target} HTTP/1.1\r\n{header_block}\r\n"
            sock.sendall(request.encode("latin-1"))
            raw = self._read_all(sock)
        except (OSError, ssl.SSLError, ValueError):
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self._last_request_ts = time.monotonic()

        return self._parse_raw_response(raw, base_url.rstrip("/") + raw_target)

    def _proxy_for(self, scheme: str, host: str) -> Optional[str]:
        target = f"{scheme}://{host}"
        try:
            if requests.utils.should_bypass_proxies(target, no_proxy=None):
                return None
        except Exception:
            pass
        proxies: Dict[str, str] = dict(self.session.proxies or {})
        if getattr(self.session, "trust_env", True):
            try:
                for key, value in requests.utils.get_environ_proxies(target, no_proxy=None).items():
                    proxies.setdefault(key, value)
            except Exception:
                pass
        return proxies.get(scheme) or proxies.get("all")

    def _wrap_tls(self, sock: socket.socket, host: str) -> ssl.SSLSocket:
        context = ssl.create_default_context()
        if not self.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(sock, server_hostname=host)

    def _raw_header_block(
        self, host: str, port: int, extra_headers: Optional[Dict[str, str]]
    ) -> str:
        host_header = host if port in (80, 443) else f"{host}:{port}"
        headers: Dict[str, str] = {
            "Host": host_header,
            "User-Agent": self.session.headers.get("User-Agent", "bb-scanner"),
            "Accept": "*/*",
            "Connection": "close",
        }
        for key, value in (self.session.headers or {}).items():
            if key.lower() in ("host", "connection", "content-length"):
                continue
            if value is not None:
                headers.setdefault(key, str(value))
        cookie = "; ".join(f"{c.name}={c.value}" for c in self.session.cookies)
        if cookie:
            headers["Cookie"] = cookie
        if extra_headers:
            headers.update(extra_headers)
        return "".join(f"{k}: {v}\r\n" for k, v in headers.items())

    @staticmethod
    def _read_headers(sock: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        return data

    def _read_all(self, sock: socket.socket) -> bytes:
        sock.settimeout(self.timeout_seconds)
        chunks = []
        total = 0
        while True:
            try:
                chunk = sock.recv(8192)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 2_000_000:  # cap at ~2 MB to stay bounded
                break
        return b"".join(chunks)

    @staticmethod
    def _parse_raw_response(raw: bytes, url: str) -> Optional[RawResponse]:
        if not raw:
            return None
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines:
            return None
        status_parts = lines[0].split(b" ", 2)
        try:
            status_code = int(status_parts[1])
        except (IndexError, ValueError):
            return None
        headers = CaseInsensitiveDict()
        for line in lines[1:]:
            if b":" in line:
                name, _, value = line.partition(b":")
                headers[name.strip().decode("latin-1")] = value.strip().decode("latin-1")
        if headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = RequestEngine._dechunk(body)
        charset = "utf-8"
        ctype = headers.get("Content-Type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            text = body.decode(charset, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        return RawResponse(status_code, headers, text, url)

    @staticmethod
    def _dechunk(body: bytes) -> bytes:
        out = bytearray()
        while body:
            size_line, _, rest = body.partition(b"\r\n")
            try:
                size = int(size_line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += rest[:size]
            body = rest[size + 2:]
        return bytes(out)
