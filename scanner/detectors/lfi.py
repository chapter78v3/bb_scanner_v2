from __future__ import annotations

from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import (
    LFI_FILE_SCHEME_PAYLOADS,
    LFI_PARAM_HINTS,
    LFI_TRAVERSAL_PAYLOADS,
    match_lfi,
)
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class LFIDetector(DetectorPlugin):
    """Detects potential local file inclusion and arbitrary file read issues.

    The detector is endpoint-agnostic: it probes any discovered URL/form parameter
    that appears file/path related instead of targeting one hardcoded route.
    """

    name = "lfi"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        payloads = self._build_payloads(context)

        for url in context.crawl.urls:
            findings.extend(self._test_url_query_params(url, engine, context, payloads))

        for form in context.crawl.forms:
            findings.extend(self._test_form(form.action_url, form.method, form.fields, engine, context, payloads))

        return findings

    def _test_url_query_params(
        self,
        url: str,
        engine: RequestEngine,
        context: ScanContext,
        payloads: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return findings

        baseline_body_l = self._safe_get_text(engine, url).lower()

        for param in params:
            if not context.lfi_aggressive and not self._looks_like_lfi_param(param):
                continue

            for payload in payloads:
                mutated = dict(params)
                mutated[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                response = self._safe_get(engine, test_url)
                if response is None:
                    continue

                sig = match_lfi(response.text)
                if sig and sig.lower() not in baseline_body_l:
                    findings.append(
                        Finding(
                            vulnerability="Potential Local File Inclusion / Arbitrary File Read",
                            severity="high",
                            cwe="CWE-98",
                            owasp="A05:2021 Security Misconfiguration",
                            url=test_url,
                            parameter=param,
                            description=(
                                "A leaked system-file signature appeared after a file/path payload "
                                "and was absent from the baseline response."
                            ),
                            evidence=f"signature={sig!r}; {self._extract_evidence(response.text)}",
                            detector=self.name,
                            confidence="medium",
                            references=["Validate manually to confirm file-read primitive and scope of access."],
                        )
                    )
                    break

        return findings

    def _test_form(self, action_url: str, method: str, fields, engine: RequestEngine, context: ScanContext, payloads: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        if not fields:
            return findings

        base = {field.name: (field.value or "scan") for field in fields}
        baseline_resp = self._safe_submit(engine, action_url, method, base)
        baseline_body_l = baseline_resp.text.lower() if baseline_resp is not None else ""

        for field in fields:
            if not context.lfi_aggressive and not self._looks_like_lfi_param(field.name):
                continue

            for payload in payloads:
                data = dict(base)
                data[field.name] = payload
                response = self._safe_submit(engine, action_url, method, data)
                if response is None:
                    continue

                sig = match_lfi(response.text)
                if sig and sig.lower() not in baseline_body_l:
                    findings.append(
                        Finding(
                            vulnerability="Potential Local File Inclusion / Arbitrary File Read",
                            severity="high",
                            cwe="CWE-98",
                            owasp="A05:2021 Security Misconfiguration",
                            url=action_url,
                            parameter=field.name,
                            description=(
                                "A leaked system-file signature appeared after a form file/path payload "
                                "and was absent from the baseline response."
                            ),
                            evidence=f"signature={sig!r}; {self._extract_evidence(response.text)}",
                            detector=self.name,
                            confidence="medium",
                            references=["Validate manually to confirm file-read primitive and scope of access."],
                        )
                    )
                    break

        return findings

    @staticmethod
    def _all_payloads() -> List[str]:
        return LFI_FILE_SCHEME_PAYLOADS + LFI_TRAVERSAL_PAYLOADS

    def _build_payloads(self, context: ScanContext) -> List[str]:
        payloads = self._all_payloads()
        if context.lfi_max_payloads > 0:
            return payloads[: context.lfi_max_payloads]
        return payloads

    @staticmethod
    def _looks_like_lfi_param(param_name: str) -> bool:
        p = param_name.lower()
        return p in LFI_PARAM_HINTS or any(hint in p for hint in LFI_PARAM_HINTS)

    @staticmethod
    def _safe_get_text(engine: RequestEngine, url: str) -> str:
        try:
            return engine.get(url).text
        except Exception:
            return ""

    @staticmethod
    def _extract_evidence(body: str, max_chars: int = 220) -> str:
        compact = " ".join(body.split())
        return compact[:max_chars]

    @staticmethod
    def _safe_get(engine: RequestEngine, url: str):
        try:
            return engine.get(url)
        except Exception:
            return None

    @staticmethod
    def _safe_submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        try:
            if method.upper() == "POST":
                return engine.post(action_url, data=data)
            return engine.get(action_url, params=data)
        except Exception:
            return None
