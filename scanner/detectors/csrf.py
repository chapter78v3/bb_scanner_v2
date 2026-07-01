from __future__ import annotations

from typing import List

from ..models import Finding, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class CSRFFDetector(DetectorPlugin):
    """Flags likely CSRF weaknesses when state-changing forms lack anti-CSRF tokens."""

    name = "csrf"

    TOKEN_KEYWORDS = ("csrf", "xsrf", "token", "authenticity")
    STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        _ = engine
        findings: List[Finding] = []

        for form in context.crawl.forms:
            method = form.method.upper()
            if method not in self.STATE_CHANGING_METHODS:
                continue

            field_names = [f.name.lower() for f in form.fields]
            has_token = any(
                any(keyword in field_name for keyword in self.TOKEN_KEYWORDS)
                for field_name in field_names
            )

            if not has_token:
                findings.append(
                    Finding(
                        vulnerability="Potential CSRF",
                        severity="medium",
                        cwe="CWE-352",
                        owasp="A01:2021 Broken Access Control",
                        url=form.action_url,
                        parameter=None,
                        description="State-changing form appears to lack an anti-CSRF token field.",
                        evidence=f"Method={method}, fields={','.join(field_names) if field_names else 'none'}",
                        detector=self.name,
                        confidence="low",
                    )
                )

        return findings
