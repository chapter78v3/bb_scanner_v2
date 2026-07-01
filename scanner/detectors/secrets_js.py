from __future__ import annotations

import math
import re
from typing import List

from ..models import Finding, ScanContext
from ..payloads import ENDPOINT_PATTERN, SECRET_PATTERNS
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class JavaScriptSecretsDetector(DetectorPlugin):
    """Scans discovered JS files for exposed credentials and suspicious endpoints."""

    name = "secrets_js"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []

        for js_url in context.crawl.js_files:
            try:
                response = engine.get(js_url)
            except Exception:
                continue

            if response.status_code >= 400:
                continue

            source = response.text

            for rule_name, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, source):
                    snippet = match.group(0)[:200]
                    entropy = self._shannon_entropy(snippet)
                    severity = "high" if ("private_key" in rule_name or entropy > 3.6) else "medium"
                    findings.append(
                        Finding(
                            vulnerability="Exposed Secret in JavaScript",
                            severity=severity,
                            cwe="CWE-798",
                            owasp="A02:2021 Cryptographic Failures",
                            url=js_url,
                            parameter=None,
                            description=f"Potential hardcoded secret matched pattern: {rule_name}.",
                            evidence=f"Snippet={snippet}",
                            detector=self.name,
                            confidence="low",
                        )
                    )

            endpoint_matches = set(re.findall(ENDPOINT_PATTERN, source))
            for endpoint in sorted(endpoint_matches)[:20]:
                if any(k in endpoint.lower() for k in ["internal", "admin", "debug", "staging", "dev"]):
                    findings.append(
                        Finding(
                            vulnerability="Suspicious Endpoint Exposed in JS",
                            severity="low",
                            cwe="CWE-200",
                            owasp="A01:2021 Broken Access Control",
                            url=js_url,
                            parameter=None,
                            description="Client-side script references potentially sensitive endpoint.",
                            evidence=endpoint,
                            detector=self.name,
                            confidence="low",
                        )
                    )

        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq = {c: data.count(c) for c in set(data)}
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
