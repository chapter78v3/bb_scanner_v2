from __future__ import annotations

import threading
import time
from typing import Dict, Optional

import requests


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
