from __future__ import annotations

import random
import secrets
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext, FormDescriptor
from ..payloads import SSTI_EXPRESSION_TEMPLATES
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class SSTIDetector(DetectorPlugin):
    """Detects Server-Side Template Injection via arithmetic evaluation.

    The detector injects a multiplication expression wrapped in a random
    sentinel across the common template-engine delimiters (``{{ }}``, ``${ }``,
    ``#{ }``, ``<%= %>`` ...). If the server renders the *product* between the
    sentinels, the template engine evaluated attacker input — a high-confidence,
    low-false-positive signal because a page that merely reflects the payload
    keeps the literal expression instead of its computed value.
    """

    name = "ssti"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        for url in context.crawl.urls:
            findings.extend(self._test_url(url, engine, context))
        for form in context.crawl.forms:
            findings.extend(self._test_form(form, engine, context))
        return findings

    def _templates(self, context: ScanContext) -> List[str]:
        templates = SSTI_EXPRESSION_TEMPLATES
        if context.ssti_max_payloads > 0:
            return templates[: context.ssti_max_payloads]
        return templates

    @staticmethod
    def _make_probe() -> Dict[str, str]:
        """Return a fresh {sentinel, expr, product} triple per injection point."""
        sentinel = "z" + secrets.token_hex(4)
        a = random.randint(1000, 9999)
        b = random.randint(1000, 9999)
        return {
            "sentinel": sentinel,
            "expr": f"{a}*{b}",
            "product": str(a * b),
        }

    def _test_url(self, url: str, engine: RequestEngine, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return findings

        baseline_body_l = self._safe_get_text(engine, url).lower()

        for param in params:
            finding = self._probe_param(
                param,
                context,
                baseline_body_l,
                lambda value, p=param: self._request_url(engine, parsed, params, p, value),
                url,
                param,
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _test_form(self, form: FormDescriptor, engine: RequestEngine, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        if not form.fields:
            return findings

        method = (form.method or "GET").upper()
        base = {field.name: (field.value or "scan") for field in form.fields}
        baseline_resp = self._safe_submit(engine, form.action_url, method, base)
        baseline_body_l = baseline_resp.text.lower() if baseline_resp is not None else ""

        for field in form.fields:
            def _submit(value, name=field.name):
                data = dict(base)
                data[name] = value
                return self._safe_submit(engine, form.action_url, method, data)

            finding = self._probe_param(
                field.name,
                context,
                baseline_body_l,
                _submit,
                form.action_url,
                field.name,
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _probe_param(self, param, context, baseline_body_l, requester, report_url, report_param):
        for template in self._templates(context):
            probe = self._make_probe()
            payload = template.format(s=probe["sentinel"], e=probe["expr"])
            marker = f"{probe['sentinel']}{probe['product']}{probe['sentinel']}"
            if marker.lower() in baseline_body_l:
                continue
            response = requester(payload)
            if response is None:
                continue
            if marker in response.text:
                return Finding(
                    vulnerability="Server-Side Template Injection",
                    severity="high",
                    cwe="CWE-1336",
                    owasp="A03:2021 Injection",
                    url=report_url,
                    parameter=report_param,
                    description=(
                        "A template expression injected into this parameter was evaluated "
                        "server-side: the multiplication product was rendered between our "
                        "sentinels instead of the literal expression, confirming template "
                        "injection (often escalatable to remote code execution)."
                    ),
                    evidence=f"payload={payload!r}; rendered_marker={marker!r}",
                    detector=self.name,
                    confidence="high",
                    references=["https://portswigger.net/research/server-side-template-injection"],
                )
        return None

    @staticmethod
    def _request_url(engine: RequestEngine, parsed, params, param, value):
        mutated = dict(params)
        mutated[param] = value
        test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        try:
            return engine.get(test_url)
        except Exception:
            return None

    @staticmethod
    def _safe_get_text(engine: RequestEngine, url: str) -> str:
        try:
            return engine.get(url).text
        except Exception:
            return ""

    @staticmethod
    def _safe_submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        try:
            if method.upper() == "POST":
                return engine.post(action_url, data=data)
            return engine.get(action_url, params=data)
        except Exception:
            return None
