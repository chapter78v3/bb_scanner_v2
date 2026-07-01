from __future__ import annotations

from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import XSS_PAYLOADS
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class XSSDetector(DetectorPlugin):
    """Detects likely reflected XSS by checking unencoded reflection in responses."""

    name = "xss"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []

        for url in context.crawl.urls:
            findings.extend(self._test_url(url, engine))

        for form in context.crawl.forms:
            findings.extend(self._test_form(form.action_url, form.method, form.fields, engine))

        return findings

    def _test_url(self, url: str, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return findings

        for param in params:
            for payload in XSS_PAYLOADS:
                mutated = dict(params)
                mutated[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                try:
                    response = engine.get(test_url)
                except Exception:
                    continue

                content_type = response.headers.get("Content-Type", "")
                if "html" not in content_type:
                    continue

                if payload in response.text:
                    findings.append(
                        Finding(
                            vulnerability="Reflected XSS",
                            severity="high",
                            cwe="CWE-79",
                            owasp="A03:2021 Injection",
                            url=test_url,
                            parameter=param,
                            description="Payload reflected in HTML response without encoding.",
                            evidence=payload,
                            detector=self.name,
                            confidence="medium",
                        )
                    )
                    break

        return findings

    def _test_form(self, action_url: str, method: str, fields, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        if not fields:
            return findings

        base = {field.name: (field.value or "scan") for field in fields}
        for field in fields:
            for payload in XSS_PAYLOADS:
                data = dict(base)
                data[field.name] = payload
                response = self._submit(engine, action_url, method, data)
                if response is None:
                    continue
                content_type = response.headers.get("Content-Type", "")
                if "html" not in content_type:
                    continue
                if payload in response.text:
                    findings.append(
                        Finding(
                            vulnerability="Reflected XSS",
                            severity="high",
                            cwe="CWE-79",
                            owasp="A03:2021 Injection",
                            url=action_url,
                            parameter=field.name,
                            description="Form payload reflected in response without output encoding.",
                            evidence=payload,
                            detector=self.name,
                            confidence="medium",
                        )
                    )
                    break

        return findings

    @staticmethod
    def _submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        try:
            if method.upper() == "POST":
                return engine.post(action_url, data=data)
            return engine.get(action_url, params=data)
        except Exception:
            return None
