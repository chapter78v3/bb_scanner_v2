from __future__ import annotations

from typing import List, Optional, Tuple


class JSRenderer:
    """Optional headless-browser renderer for JavaScript-driven applications.

    Uses Playwright when available so the crawler can see DOM content and links
    injected at runtime by SPA frameworks (React/Angular/Vue). If Playwright is
    not installed, the renderer degrades gracefully and the crawler falls back
    to static HTML parsing.

    Install with:  pip install playwright  &&  python -m playwright install chromium
    """

    def __init__(self, timeout_ms: int = 15000, wait_until: str = "networkidle") -> None:
        self.timeout_ms = timeout_ms
        self.wait_until = wait_until
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        if self._available is None:
            try:
                import playwright  # noqa: F401

                self._available = True
            except Exception:
                self._available = False
        return self._available

    def render(
        self,
        url: str,
        headers: Optional[dict] = None,
        verify_tls: bool = True,
    ) -> Optional[Tuple[str, List[str]]]:
        """Render ``url`` and return (html, discovered_urls), or None on failure.

        Discovered URLs include anchors present in the post-render DOM. Network
        errors and missing Playwright both return None so callers can fall back.
        """
        if not self.is_available():
            return None

        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    ignore_https_errors=not verify_tls,
                    extra_http_headers=headers or {},
                )
                page = context.new_page()
                page.goto(url, timeout=self.timeout_ms, wait_until=self.wait_until)
                html = page.content()
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
                browser.close()
                return html, [h for h in hrefs if isinstance(h, str) and h]
        except Exception:
            return None

    def probe_dom_xss(
        self,
        url: str,
        token: str,
        headers: Optional[dict] = None,
        verify_tls: bool = True,
    ) -> bool:
        """Navigate ``url`` and report whether a JS dialog fired with ``token``.

        The caller injects a payload such as ``<img src=x onerror=alert('TOKEN')>``
        or ``javascript:alert('TOKEN')`` into a parameter/fragment. If the token
        is echoed into a DOM sink and executes, Playwright observes the dialog
        and this returns True — real, execution-confirmed DOM XSS.
        """
        if not self.is_available():
            return False

        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return False

        fired = {"hit": False}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    ignore_https_errors=not verify_tls,
                    extra_http_headers=headers or {},
                )
                page = context.new_page()

                def _on_dialog(dialog):
                    try:
                        if token in (dialog.message or ""):
                            fired["hit"] = True
                    finally:
                        try:
                            dialog.dismiss()
                        except Exception:
                            pass

                page.on("dialog", _on_dialog)
                page.goto(url, timeout=self.timeout_ms, wait_until=self.wait_until)
                page.wait_for_timeout(800)
                browser.close()
        except Exception:
            return fired["hit"]

        return fired["hit"]
