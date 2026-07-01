from __future__ import annotations

from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import SSRF_PARAM_HINTS, SSRF_TEST_VALUES
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class SSRFDetector(DetectorPlugin):
    """Heuristic SSRF detector for URL-like parameters."""

    name = "ssrf"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []

        for url in context.crawl.urls:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not params:
                continue

            for param in params:
                if not self._looks_like_ssrf_param(param):
                    continue

                findings.extend(self._blind_probe(parsed, params, param, context, engine))

                for probe in SSRF_TEST_VALUES:
                    mutated = dict(params)
                    mutated[param] = probe
                    test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                    try:
                        response = engine.get(test_url)
                    except Exception:
                        continue

                    body_l = response.text.lower()
                    if any(marker in body_l for marker in ["connection refused", "localhost", "127.0.0.1", "timed out"]):
                        findings.append(
                            Finding(
                                vulnerability="Potential SSRF",
                                severity="high",
                                cwe="CWE-918",
                                owasp="A10:2021 SSRF",
                                url=test_url,
                                parameter=param,
                                description="Endpoint exhibited SSRF-like behavior after URL probe.",
                                evidence=f"Probe={probe}; status={response.status_code}",
                                detector=self.name,
                                confidence="low",
                                references=["Out-of-band SSRF validation recommended."],
                            )
                        )
                        break

        return findings

    @staticmethod
    def _looks_like_ssrf_param(param_name: str) -> bool:
        lname = param_name.lower()
        return lname in SSRF_PARAM_HINTS or any(hint in lname for hint in SSRF_PARAM_HINTS)

    def _blind_probe(self, parsed, params, param, context, engine) -> List[Finding]:
        """Inject an out-of-band callback host to surface *blind* SSRF.

        Requires a configured OAST client (``--oast-server``). The unique
        callback host is embedded in the parameter; any interaction recorded
        by the operator's collaborator confirms server-side request egress.
        """
        findings: List[Finding] = []
        oast = getattr(context, "oast", None)
        if oast is None or not getattr(oast, "enabled", False):
            return findings

        correlation_id = f"ssrf|{parsed.path}|{param}"
        host = oast.new_payload_host(correlation_id)
        if not host:
            return findings

        callback_url = f"http://{host}/"
        mutated = dict(params)
        mutated[param] = callback_url
        test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        try:
            engine.get(test_url)
        except Exception:
            return findings

        findings.append(
            Finding(
                vulnerability="Blind SSRF Probe Dispatched",
                severity="info",
                cwe="CWE-918",
                owasp="A10:2021 SSRF",
                url=test_url,
                parameter=param,
                description=(
                    "An out-of-band SSRF payload was sent. Confirm exploitation by checking "
                    "your collaborator/OAST listener for an interaction from this callback host."
                ),
                evidence=f"callback={callback_url}; correlation={correlation_id}",
                detector=self.name,
                confidence="low",
                references=["https://portswigger.net/web-security/ssrf/blind"],
            )
        )
        return findings
