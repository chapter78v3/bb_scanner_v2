from __future__ import annotations

from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import IDOR_PARAM_HINTS
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class IDORDetector(DetectorPlugin):
    """Heuristic IDOR detector by mutating identifier-like parameters."""

    name = "idor"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        secondary = getattr(context, "secondary_engine", None)

        for url in context.crawl.urls:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not params:
                continue

            for param, value in params.items():
                if not self._is_identifier_param(param, value):
                    continue

                # Strongest signal: cross-identity access control (BOLA). If a
                # second authenticated identity can read identity A's object,
                # authorization is broken regardless of ID guessability.
                if secondary is not None:
                    findings.extend(
                        self._cross_identity_check(engine, secondary, url, param, value)
                    )

                baseline_status, baseline_len = self._fetch_signature(engine, url)
                tampered_value = self._mutate_identifier(value)
                if tampered_value == value:
                    continue
                mutated = dict(params)
                mutated[param] = tampered_value
                test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                tampered_status, tampered_len = self._fetch_signature(engine, test_url)

                if baseline_status is None or tampered_status is None:
                    continue

                same_status = baseline_status == tampered_status
                similar_len = abs((baseline_len or 0) - (tampered_len or 0)) < 80

                if same_status and similar_len and baseline_status == 200:
                    findings.append(
                        Finding(
                            vulnerability="Potential IDOR",
                            severity="high" if context.authenticated else "medium",
                            cwe="CWE-639",
                            owasp="A01:2021 Broken Access Control",
                            url=test_url,
                            parameter=param,
                            description="ID parameter tampering returned a similar successful response.",
                            evidence=(
                                f"Original={value}, Tampered={tampered_value}, "
                                f"Status={tampered_status}, len_diff={abs((baseline_len or 0) - (tampered_len or 0))}"
                            ),
                            detector=self.name,
                            confidence="low",
                            references=[
                                "Verify with multiple authenticated identities for robust IDOR validation."
                            ],
                        )
                    )

        return findings

    def _cross_identity_check(
        self,
        primary: RequestEngine,
        secondary: RequestEngine,
        url: str,
        param: str,
        value: str,
    ) -> List[Finding]:
        """Compare access to identity A's object from a second identity (BOLA)."""
        findings: List[Finding] = []
        a_status, a_len = self._fetch_signature(primary, url)
        b_status, b_len = self._fetch_signature(secondary, url)

        if a_status is None or b_status is None:
            return findings

        # Identity A can read the object (200) and identity B gets an equally
        # successful, near-identical response => broken object-level authz.
        if a_status == 200 and b_status == 200 and abs((a_len or 0) - (b_len or 0)) < 80:
            findings.append(
                Finding(
                    vulnerability="Broken Object Level Authorization (IDOR/BOLA)",
                    severity="high",
                    cwe="CWE-639",
                    owasp="A01:2021 Broken Access Control",
                    url=url,
                    parameter=param,
                    description=(
                        "A second authenticated identity received a successful, near-identical "
                        "response for another identity's object, indicating missing authorization checks."
                    ),
                    evidence=(
                        f"id={value}; identityA_status={a_status} len={a_len}; "
                        f"identityB_status={b_status} len={b_len}"
                    ),
                    detector=self.name,
                    confidence="high",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                )
            )
        return findings

    @staticmethod
    def _is_identifier_param(param: str, value: str) -> bool:
        p = param.lower()
        if p in IDOR_PARAM_HINTS or p.endswith("id"):
            return True
        return value.isdigit()

    @staticmethod
    def _mutate_identifier(value: str) -> str:
        if value.isdigit():
            num = int(value)
            return str(num + 1 if num >= 0 else num - 1)
        if len(value) >= 8 and value.isalnum():
            return value[:-1] + ("0" if value[-1] != "0" else "1")
        return value

    @staticmethod
    def _fetch_signature(engine: RequestEngine, url: str):
        try:
            response = engine.get(url)
        except Exception:
            return None, None
        return response.status_code, len(response.text)
