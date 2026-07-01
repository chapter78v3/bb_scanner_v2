"""CORS misconfiguration detector.

Actively probes each discovered endpoint with a crafted ``Origin`` request
header and inspects the ``Access-Control-Allow-Origin`` (ACAO) and
``Access-Control-Allow-Credentials`` (ACAC) response headers for the classic
trust-boundary failures that let a malicious site read authenticated
responses:

* ACAO reflecting an *arbitrary* attacker origin,
* ACAO accepting the special ``null`` origin,
* ACAO trusting an unvalidated subdomain / prefix / suffix of the target, and
* any of the above combined with ``ACAC: true`` (credentialed) -> high impact.

All probes are read-only GET requests; no state is changed on the target.
"""

from __future__ import annotations

from typing import List, Set, Tuple
from urllib.parse import urlparse

from ..models import Finding, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

# Cap the number of distinct endpoints probed so large crawls stay bounded.
MAX_ENDPOINTS = 60

# Attacker-controlled origin used to detect blanket reflection.
EVIL_ORIGIN = "https://evil-cors-probe.example"


class CORSMisconfigurationDetector(DetectorPlugin):
    """Detect permissive / reflected Cross-Origin Resource Sharing policies."""

    name = "cors"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()

        for url in self._candidate_urls(context):
            key = self._endpoint_key(url)
            if key in seen:
                continue
            seen.add(key)
            if len(seen) > MAX_ENDPOINTS:
                break
            findings.extend(self._probe(url, engine))

        return findings

    def _candidate_urls(self, context: ScanContext) -> List[str]:
        urls: List[str] = []
        if context.target_url:
            urls.append(context.target_url)
        urls.extend(context.crawl.urls)
        return urls

    @staticmethod
    def _endpoint_key(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _origin_variants(self, url: str) -> List[Tuple[str, str, str]]:
        """Return (origin, label, severity_hint) probes tailored to the host."""
        host = urlparse(url).hostname or ""
        variants: List[Tuple[str, str, str]] = [
            (EVIL_ORIGIN, "arbitrary origin reflected", "high"),
            ("null", "null origin trusted", "high"),
        ]
        if host:
            # Suffix bypass: attacker registers <target>.evil.com
            variants.append((f"https://{host}.evil-cors-probe.example", "suffix bypass (host as subdomain of attacker)", "high"))
            # Prefix / not-anchored bypass: attacker registers evil<target>
            variants.append((f"https://evil-cors-probe{host}", "prefix bypass (unanchored host match)", "high"))
            # Untrusted subdomain of the target itself
            variants.append((f"https://evil-cors-probe.{host}", "arbitrary subdomain trusted", "medium"))
        return variants

    def _probe(self, url: str, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        for origin, label, sev_hint in self._origin_variants(url):
            try:
                response = engine.get(url, headers={"Origin": origin})
            except Exception:
                continue

            acao = response.headers.get("Access-Control-Allow-Origin")
            if not acao:
                continue
            acac = (response.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
            credentialed = acac == "true"

            reflected = self._is_dangerous(origin, acao)
            if not reflected:
                continue

            severity = "high" if credentialed else ("medium" if sev_hint == "high" else "low")
            confidence = "high" if credentialed else "medium"
            cred_note = (
                "with 'Access-Control-Allow-Credentials: true' — a malicious page can read "
                "authenticated, cross-origin responses (cookies/session)."
                if credentialed
                else "without credentials — impact limited to unauthenticated responses, but still a policy weakness."
            )
            findings.append(
                Finding(
                    vulnerability="CORS Misconfiguration",
                    severity=severity,
                    cwe="CWE-942",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                    parameter="Origin",
                    description=(
                        f"Endpoint reflects an untrusted Origin ({label}) in "
                        f"Access-Control-Allow-Origin {cred_note}"
                    ),
                    evidence=(
                        f"Sent Origin: {origin} -> ACAO: {acao}; "
                        f"ACAC: {acac or 'absent'}"
                    ),
                    detector=self.name,
                    confidence=confidence,
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "OWASP: Testing Cross Origin Resource Sharing (WSTG-CLNT-07)",
                    ],
                )
            )
            # One confirmed dangerous policy per endpoint is enough signal.
            break
        return findings

    @staticmethod
    def _is_dangerous(sent_origin: str, acao: str) -> bool:
        acao_stripped = acao.strip()
        # Exact reflection of our attacker origin is always dangerous.
        if acao_stripped == sent_origin:
            return True
        # 'null' is exploitable via sandboxed iframes / data: documents.
        if sent_origin == "null" and acao_stripped.lower() == "null":
            return True
        return False
