from __future__ import annotations

from typing import Dict, List, Optional

from ..models import Finding, ScanContext
from ..payloads import (
    XXE_BASELINE_BODY,
    XXE_CONTENT_TYPES,
    XXE_INBAND_TEMPLATES,
    XXE_OOB_TEMPLATE,
    XXE_TARGET_FILES,
    match_lfi,
)
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

_MAX_ENDPOINTS = 25


class XXEDetector(DetectorPlugin):
    """Detects XML External Entity injection in XML-accepting endpoints.

    For each candidate endpoint the detector posts a crafted XML document whose
    external entity resolves either a local file (in-band disclosure, confirmed
    with the shared leaked-file signatures and a baseline-absence check) or an
    out-of-band callback host (blind XXE, confirmed by the collaborator).
    """

    name = "xxe"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        for endpoint in self._candidate_endpoints(context):
            findings.extend(self._test_endpoint(endpoint, engine, context))
        return findings

    def _candidate_endpoints(self, context: ScanContext) -> List[str]:
        """Prefer endpoints that look XML-aware, then form actions and the root."""
        endpoints: List[str] = []

        def _add(url: str) -> None:
            if url and url not in endpoints:
                endpoints.append(url)

        for obs in context.crawl.observations:
            if any(ct in (obs.content_type or "").lower() for ct in XXE_CONTENT_TYPES):
                _add(obs.url)
        for form in context.crawl.forms:
            if (form.method or "").upper() == "POST":
                _add(form.action_url)
        _add(context.target_url)
        return endpoints[:_MAX_ENDPOINTS]

    def _test_endpoint(self, url: str, engine: RequestEngine, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        baseline = self._post_xml(engine, url, XXE_BASELINE_BODY)
        baseline_body_l = baseline.text.lower() if baseline is not None else ""

        for template in self._inband_templates(context):
            for file_uri in XXE_TARGET_FILES:
                body = template.format(file=file_uri)
                response = self._post_xml(engine, url, body)
                if response is None:
                    continue
                sig = match_lfi(response.text)
                if sig and sig.lower() not in baseline_body_l:
                    findings.append(
                        Finding(
                            vulnerability="XML External Entity (XXE) Injection",
                            severity="high",
                            cwe="CWE-611",
                            owasp="A05:2021 Security Misconfiguration",
                            url=url,
                            parameter=None,
                            description=(
                                "An XML document with an external entity pointing at a local file "
                                "caused a leaked-file signature to appear in the response that was "
                                "absent from the baseline, confirming the parser resolves external "
                                "entities (file disclosure / XXE)."
                            ),
                            evidence=f"entity={file_uri!r}; signature={sig!r}",
                            detector=self.name,
                            confidence="high",
                            references=["https://portswigger.net/web-security/xxe"],
                        )
                    )
                    return findings  # one confirmed in-band hit per endpoint is enough

        findings.extend(self._oob_probe(url, engine, context))
        return findings

    def _oob_probe(self, url: str, engine: RequestEngine, context: ScanContext) -> List[Finding]:
        oast = getattr(context, "oast", None)
        if oast is None or not getattr(oast, "enabled", False):
            return []
        correlation_id = f"xxe|{url}"
        host = oast.new_payload_host(correlation_id)
        if not host:
            return []
        self._post_xml(engine, url, XXE_OOB_TEMPLATE.format(host=host))
        return [
            Finding(
                vulnerability="Blind XXE Probe Dispatched",
                severity="info",
                cwe="CWE-611",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
                parameter=None,
                description=(
                    "An out-of-band XXE payload was posted. Confirm exploitation by checking your "
                    "collaborator/OAST listener for an interaction from this callback host."
                ),
                evidence=f"callback_host={host}; correlation={correlation_id}",
                detector=self.name,
                confidence="low",
                references=["https://portswigger.net/web-security/xxe/blind"],
            )
        ]

    def _inband_templates(self, context: ScanContext) -> List[str]:
        templates = XXE_INBAND_TEMPLATES
        if context.xxe_max_payloads > 0:
            return templates[: context.xxe_max_payloads]
        return templates

    @staticmethod
    def _post_xml(engine: RequestEngine, url: str, body: str):
        try:
            return engine.post(
                url,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/xml"},
            )
        except Exception:
            return None
