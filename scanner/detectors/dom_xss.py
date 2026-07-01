from __future__ import annotations

import secrets
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class DomXssDetector(DetectorPlugin):
    """Execution-confirmed DOM-based XSS via the headless-browser renderer.

    Unlike reflected-XSS substring matching, this injects an executing payload
    and only reports when the browser actually fires a dialog carrying our
    unique token, eliminating false positives. Runs only when a JS renderer is
    available (``--render-js`` with Playwright installed); otherwise it no-ops.
    """

    name = "dom_xss"

    # Payload templates parameterized by a unique token; each targets a common
    # DOM sink / breakout context.
    PAYLOAD_TEMPLATES = (
        "\"><img src=x onerror=alert('{token}')>",
        "'><img src=x onerror=alert('{token}')>",
        "javascript:alert('{token}')",
        "\"-alert('{token}')-\"",
    )

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        _ = engine
        findings: List[Finding] = []
        renderer = getattr(context, "renderer", None)
        if renderer is None or not renderer.is_available():
            return findings

        headers = {}
        verify_tls = True

        for url in context.crawl.urls:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))

            # Test each existing query parameter as a candidate DOM sink source.
            for param in params:
                if self._probe_param(renderer, parsed, params, param, headers, verify_tls, findings):
                    break

            # Also test the URL fragment, a very common DOM-XSS source.
            self._probe_fragment(renderer, url, parsed, headers, verify_tls, findings)

        return findings

    def _probe_param(self, renderer, parsed, params, param, headers, verify_tls, findings) -> bool:
        for template in self.PAYLOAD_TEMPLATES:
            token = "domxss" + secrets.token_hex(4)
            payload = template.format(token=token)
            mutated = dict(params)
            mutated[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            if renderer.probe_dom_xss(test_url, token, headers=headers, verify_tls=verify_tls):
                findings.append(
                    Finding(
                        vulnerability="DOM-based XSS (execution confirmed)",
                        severity="high",
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                        url=test_url,
                        parameter=param,
                        description="Injected payload executed in the browser DOM, confirmed via dialog interception.",
                        evidence=f"payload={payload}; token={token}",
                        detector=self.name,
                        confidence="high",
                        references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                    )
                )
                return True
        return False

    def _probe_fragment(self, renderer, url, parsed, headers, verify_tls, findings) -> None:
        for template in self.PAYLOAD_TEMPLATES:
            token = "domxss" + secrets.token_hex(4)
            payload = template.format(token=token)
            base = urlunparse(parsed._replace(fragment=""))
            test_url = f"{base}#{payload}"
            if renderer.probe_dom_xss(test_url, token, headers=headers, verify_tls=verify_tls):
                findings.append(
                    Finding(
                        vulnerability="DOM-based XSS via URL fragment (execution confirmed)",
                        severity="high",
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                        url=test_url,
                        parameter="#fragment",
                        description="URL fragment flowed into a DOM sink and executed, confirmed via dialog interception.",
                        evidence=f"payload={payload}; token={token}",
                        detector=self.name,
                        confidence="high",
                        references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                    )
                )
                return
