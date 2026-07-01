from __future__ import annotations

from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from ..models import Finding, PageObservation, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class PassiveHeadersDetector(DetectorPlugin):
    """Passively evaluates response headers and cookies from crawl observations.

    Sends no additional requests: it only inspects metadata already captured
    during crawling, making it zero added attack surface and very high signal.
    Findings are de-duplicated per host so one weak header is reported once.
    """

    name = "passive"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        _ = engine
        findings: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()

        for obs in context.crawl.observations:
            host = urlparse(obs.url).netloc
            is_https = urlparse(obs.url).scheme == "https"

            for finding in self._check_headers(obs, host, is_https):
                key = (host, finding.vulnerability)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)

            for finding in self._check_cookies(obs, host, is_https):
                key = (host, finding.vulnerability + (finding.evidence.split(";")[0]))
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)

        return findings

    def _check_headers(self, obs: PageObservation, host: str, is_https: bool) -> List[Finding]:
        findings: List[Finding] = []
        headers = {k.lower(): v for k, v in obs.headers.items()}

        # Only assess header hygiene on HTML documents to reduce noise.
        if "html" not in obs.content_type.lower():
            return findings

        if "content-security-policy" not in headers:
            findings.append(
                self._make(
                    "Missing Content-Security-Policy Header",
                    "medium",
                    "CWE-693",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "Response does not set a Content-Security-Policy, weakening defense-in-depth against XSS and data injection.",
                    "Content-Security-Policy header absent",
                    ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"],
                )
            )

        xfo = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()
        if "frame-ancestors" not in csp and xfo not in ("deny", "sameorigin"):
            findings.append(
                self._make(
                    "Clickjacking: Missing Frame Protection",
                    "medium",
                    "CWE-1021",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "No X-Frame-Options or CSP frame-ancestors directive was found; the page may be framed for clickjacking.",
                    f"X-Frame-Options={xfo or 'absent'}",
                    ["https://owasp.org/www-community/attacks/Clickjacking"],
                )
            )

        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(
                self._make(
                    "Missing X-Content-Type-Options: nosniff",
                    "low",
                    "CWE-693",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "Response does not set X-Content-Type-Options: nosniff, allowing MIME-type sniffing.",
                    f"X-Content-Type-Options={headers.get('x-content-type-options', 'absent')}",
                    ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                )
            )

        if is_https and "strict-transport-security" not in headers:
            findings.append(
                self._make(
                    "Missing HTTP Strict Transport Security (HSTS)",
                    "medium",
                    "CWE-319",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "HTTPS response does not set Strict-Transport-Security, leaving clients open to protocol downgrade.",
                    "Strict-Transport-Security header absent",
                    ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                )
            )

        # Permissive CORS observed passively (no Origin sent, so a wildcard is
        # unambiguously permissive; credentialed wildcard is disallowed by spec
        # but reflected origins with credentials are a common real bug).
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(
                self._make(
                    "CORS Misconfiguration: Wildcard Origin with Credentials",
                    "high",
                    "CWE-942",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true, an unsafe combination.",
                    f"ACAO={acao}; ACAC={acac}",
                    ["https://portswigger.net/web-security/cors"],
                )
            )
        elif acao == "*":
            findings.append(
                self._make(
                    "CORS: Wildcard Access-Control-Allow-Origin",
                    "low",
                    "CWE-942",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "Access-Control-Allow-Origin is set to '*'; verify no sensitive data is served from this endpoint.",
                    f"ACAO={acao}",
                    ["https://portswigger.net/web-security/cors"],
                )
            )

        disclosed = []
        for header_name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            value = obs.headers.get(header_name) or obs.headers.get(header_name.title())
            if value and any(ch.isdigit() for ch in value):
                disclosed.append(f"{header_name}: {value}")
        if disclosed:
            findings.append(
                self._make(
                    "Server Version Disclosure",
                    "low",
                    "CWE-200",
                    "A05:2021 Security Misconfiguration",
                    obs.url,
                    "Response headers disclose software/version details that aid targeted attacks.",
                    "; ".join(disclosed),
                    ["https://owasp.org/www-project-web-security-testing-guide/"],
                )
            )

        return findings

    def _check_cookies(self, obs: PageObservation, host: str, is_https: bool) -> List[Finding]:
        findings: List[Finding] = []
        for raw in obs.set_cookie:
            attrs = [part.strip() for part in raw.split(";")]
            name = attrs[0].split("=", 1)[0] if attrs else "cookie"
            lowered = [a.lower() for a in attrs]

            missing = []
            if is_https and not any(a == "secure" for a in lowered):
                missing.append("Secure")
            if not any(a == "httponly" for a in lowered):
                missing.append("HttpOnly")
            if not any(a.startswith("samesite") for a in lowered):
                missing.append("SameSite")

            if missing:
                findings.append(
                    self._make(
                        "Insecure Cookie Attributes",
                        "medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                        "CWE-614",
                        "A05:2021 Security Misconfiguration",
                        obs.url,
                        f"Cookie '{name}' is missing recommended security attributes: {', '.join(missing)}.",
                        f"{name}; missing={','.join(missing)}",
                        ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    )
                )
        return findings

    def _make(
        self,
        vulnerability: str,
        severity: str,
        cwe: str,
        owasp: str,
        url: str,
        description: str,
        evidence: str,
        references: List[str],
    ) -> Finding:
        return Finding(
            vulnerability=vulnerability,
            severity=severity,
            cwe=cwe,
            owasp=owasp,
            url=url,
            parameter=None,
            description=description,
            evidence=evidence,
            detector=self.name,
            confidence="high",
            references=references,
        )
