"""Open redirect detector.

Finds endpoints that redirect the browser to an attacker-controlled URL taken
from a request parameter without validating it against an allow-list. Open
redirects are frequently chained into phishing, OAuth ``redirect_uri`` theft,
and SSRF/filter bypasses.

For every URL parameter that looks like a redirect target, the detector swaps
in a series of off-site canary payloads (including common filter-bypass forms
such as scheme-relative ``//host`` and backslash tricks) and inspects the
response — both the ``Location`` header of a 3xx and any HTML
``meta http-equiv="refresh"`` / JavaScript ``location`` assignment — for the
canary host. Requests are sent with redirects disabled so the browser is never
actually navigated off-site.
"""

from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import OPEN_REDIRECT_CANARY, REDIRECT_PARAM_HINTS
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

MAX_ENDPOINTS = 80

# Canary payloads: absolute, scheme-relative, and common filter-bypass encodings.
_PAYLOADS = (
    f"https://{OPEN_REDIRECT_CANARY}",
    f"//{OPEN_REDIRECT_CANARY}",
    f"https:{OPEN_REDIRECT_CANARY}",
    f"/\\{OPEN_REDIRECT_CANARY}",
    f"https://{OPEN_REDIRECT_CANARY}/%2f%2e%2e",
)

_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+url=([^'">\s]+)""",
    re.IGNORECASE,
)
_JS_LOCATION_RE = re.compile(
    r"""(?:location(?:\.href|\.replace\(|\.assign\()?|window\.location)\s*=?\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class OpenRedirectDetector(DetectorPlugin):
    """Detect unvalidated redirects to attacker-controlled destinations."""

    name = "open_redirect"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()

        for url in context.crawl.urls:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not params:
                continue

            for param in params:
                if not self._looks_like_redirect_param(param):
                    continue
                key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}"
                if key in seen:
                    continue
                seen.add(key)
                if len(seen) > MAX_ENDPOINTS:
                    return findings

                finding = self._probe_param(parsed, params, param, engine)
                if finding is not None:
                    findings.append(finding)

        return findings

    @staticmethod
    def _looks_like_redirect_param(param_name: str) -> bool:
        lname = param_name.lower()
        return lname in REDIRECT_PARAM_HINTS

    def _probe_param(self, parsed, params, param, engine: RequestEngine):
        for payload in _PAYLOADS:
            mutated = dict(params)
            mutated[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            try:
                response = engine.get(test_url, allow_redirects=False)
            except Exception:
                continue

            location = response.headers.get("Location", "")
            channel = self._redirect_targets_canary(location, test_url)
            if channel:
                return self._build_finding(test_url, param, payload, channel, f"Location: {location}", "high")

            # Fall back to body-based redirects (meta refresh / JS) on 2xx pages.
            if 200 <= response.status_code < 300:
                body_hit = self._body_targets_canary(response.text, test_url)
                if body_hit:
                    channel_name, evidence = body_hit
                    return self._build_finding(test_url, param, payload, channel_name, evidence, "medium")
        return None

    def _redirect_targets_canary(self, location: str, base_url: str) -> str:
        if not location:
            return ""
        resolved = urljoin(base_url, location)
        host = (urlparse(resolved).hostname or "").lower()
        if host == OPEN_REDIRECT_CANARY:
            return "HTTP Location header"
        # Scheme-relative //host that some servers echo verbatim.
        if location.lstrip().lower().startswith(f"//{OPEN_REDIRECT_CANARY}"):
            return "HTTP Location header"
        return ""

    def _body_targets_canary(self, body: str, base_url: str):
        if OPEN_REDIRECT_CANARY not in (body or "").lower():
            return None
        for regex, channel in ((_META_REFRESH_RE, "HTML meta refresh"), (_JS_LOCATION_RE, "JavaScript location assignment")):
            for match in regex.finditer(body):
                candidate = match.group(1)
                resolved = urljoin(base_url, candidate)
                if (urlparse(resolved).hostname or "").lower() == OPEN_REDIRECT_CANARY:
                    return channel, f"{channel}: {candidate.strip()[:200]}"
        return None

    def _build_finding(self, test_url, param, payload, channel, evidence, severity) -> Finding:
        return Finding(
            vulnerability="Open Redirect",
            severity=severity,
            cwe="CWE-601",
            owasp="A01:2021 Broken Access Control",
            url=test_url,
            parameter=param,
            description=(
                f"Parameter '{param}' redirects to an attacker-controlled destination "
                f"without validation (via {channel}). Exploitable for phishing and "
                f"OAuth redirect_uri theft."
            ),
            evidence=f"Payload={payload}; {evidence}",
            detector=self.name,
            confidence="high" if channel == "HTTP Location header" else "medium",
            references=[
                "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            ],
        )
