from __future__ import annotations

import json
import os
from html import escape
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import Finding


class ReportingEngine:
    """Handles console and JSON reporting for scan findings."""

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    @staticmethod
    def _ensure_reports_dir() -> str:
        reports_dir = os.path.join(os.getcwd(), "Reports")
        os.makedirs(reports_dir, exist_ok=True)
        return reports_dir

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in value)
        while "__" in safe:
            safe = safe.replace("__", "_")
        return safe.strip("_") or "report"

    def summarize_console(self, findings: List[Finding], stats: Dict[str, Any] | None = None) -> None:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            sev = finding.severity.lower()
            if sev in counts:
                counts[sev] += 1

        print("\n=== Scan Summary ===")
        print(f"Total findings: {len(findings)}")
        print(
            "Severity counts: "
            f"critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}"
        )

        for finding in findings[:15]:
            print(
                f"- [{finding.severity.upper()}] {finding.vulnerability} at {finding.url}"
                f" (param={finding.parameter or 'n/a'})"
            )

        if len(findings) > 15:
            print(f"... and {len(findings) - 15} more findings in JSON report")

        if stats:
            discovery = stats.get("discovery", {})
            print("\n=== Coverage Diagnostics ===")
            print(
                "Discovery: "
                f"urls={discovery.get('urls', 0)}, "
                f"pages_fetched={discovery.get('pages_fetched', 0)}, "
                f"forms={discovery.get('forms', 0)}, "
                f"js_files={discovery.get('js_files', 0)}, "
                f"fetch_errors={discovery.get('fetch_errors', 0)}"
            )
            cd = stats.get("content_discovery", {})
            if cd.get("enabled"):
                print(
                    "Content discovery: "
                    f"paths_discovered={cd.get('paths_discovered', 0)}, "
                    f"sensitive_findings={cd.get('sensitive_findings', 0)}"
                )
            nuclei = stats.get("nuclei", {})
            if nuclei.get("enabled"):
                if nuclei.get("available"):
                    print(
                        "Nuclei: "
                        f"targets={nuclei.get('targets', 0)}, "
                        f"findings={nuclei.get('templates_matched', 0)}, "
                        f"runtime_ms={nuclei.get('runtime_ms', 0)}"
                    )
                else:
                    print(f"Nuclei: enabled but skipped ({nuclei.get('skipped_reason', 'unavailable')})")
            kb = stats.get("knowledge_base", {})
            if kb.get("enabled"):
                print(
                    "Knowledge base: "
                    f"host_findings={kb.get('host_findings', 0)}, "
                    f"hotspots_seeded={kb.get('seed_urls_added', 0)}, "
                    f"regressions_flagged={kb.get('regressions_flagged', 0)}"
                )
                if kb.get("generalize"):
                    print(f"  Generalization: probing {kb.get('learned_paths_probed', 0)} learned path pattern(s) on this host")
                if kb.get("learn"):
                    line = f"  Self-learning: recorded {kb.get('learned_new', 0)} new confirmed finding(s) into the knowledge base"
                    if kb.get("learn_error"):
                        line += f" (save failed: {kb.get('learn_error')})"
                    print(line)
            for detector in stats.get("detectors", []):
                error = detector.get("error")
                status = "error" if error else "ok"
                print(
                    f"- detector={detector.get('name')} status={status} "
                    f"findings={detector.get('findings', 0)} "
                    f"time_ms={detector.get('duration_ms', 0)}"
                )
            sqli_probes = stats.get("sqli_probes", [])
            if sqli_probes:
                print(f"SQLi probe artifacts captured: {len(sqli_probes)}")

            self._print_actionable_hints(findings, discovery, stats)

    def _print_actionable_hints(
        self, findings: List[Finding], discovery: Dict[str, Any], stats: Dict[str, Any]
    ) -> None:
        """Explain *why* a scan may have found nothing and what to change."""
        sample_errors = discovery.get("sample_errors", []) or []
        pages_fetched = discovery.get("pages_fetched", 0)
        fetch_errors = discovery.get("fetch_errors", 0)
        config = stats.get("configuration", {}) or {}

        if sample_errors:
            print("\n=== Why the scan may be empty ===")
            print(f"{fetch_errors} page fetch(es) failed. First failures:")
            saw_tls = False
            for err in sample_errors[:5]:
                etype = err.get("error_type", "Error")
                print(f"  - {err.get('url')}  ->  {etype}: {err.get('error', '')[:160]}")
                if "SSL" in etype or "Certificate" in etype or "CERTIFICATE" in str(err.get("error", "")).upper():
                    saw_tls = True
            if saw_tls:
                print("  Hint: TLS certificate verification failed. If you trust this host, re-run with --insecure.")

        if pages_fetched == 0 and not sample_errors:
            print("\nHint: no pages were successfully fetched. Check the URL, auth cookies/headers, or network path (proxy?).")

        # No successful discovery of parameters + injection detectors were idle.
        if not findings:
            no_params = all("?" not in u for u in discovery.get("sample_urls", []))
            aggressive = config.get("sqli_aggressive")
            if no_params and not aggressive:
                print(
                    "\nHint: the target URL has no query parameters, so injection detectors had nothing to test.\n"
                    "  Try one of:\n"
                    "    * add parameterized endpoints:  --seed-url \"https://host/path?param=value\"\n"
                    "    * guess parameters automatically:  --sqli-aggressive --sqli-param <name>\n"
                    "    * increase crawl reach:  --max-pages 50  (and --render-js for SPA/JS apps)"
                )

    def write_json_report(self, findings: List[Finding], target_url: str, stats: Dict[str, Any] | None = None) -> None:
        report = {
            "tool": "bb_scanner_v2",
            "authorized_use_notice": "Authorized use only. Do not scan systems without permission.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target_url,
            "total_findings": len(findings),
            "findings": [asdict(finding) for finding in findings],
            "coverage": stats or {},
        }
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    def write_html_report(self, findings: List[Finding], target_url: str, stats: Dict[str, Any] | None = None) -> str:
        reports_dir = self._ensure_reports_dir()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        target_slug = self._sanitize_filename(target_url.replace("https://", "").replace("http://", ""))
        html_path = os.path.join(reports_dir, f"{target_slug}_{ts}.html")

        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            sev = finding.severity.lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        findings_rows = "\n".join(
            "<tr>"
            f"<td>{escape(f.severity.upper())}</td>"
            f"<td>{escape(f.vulnerability)}</td>"
            f"<td>{escape(f.url)}</td>"
            f"<td>{escape(f.parameter or 'n/a')}</td>"
            f"<td>{escape(f.cwe)}</td>"
            f"<td>{escape(f.owasp)}</td>"
            f"<td>{escape(f.evidence[:180])}</td>"
            "</tr>"
            for f in findings
        )
        if not findings_rows:
            findings_rows = "<tr><td colspan='7'>No findings detected.</td></tr>"

        discovery = (stats or {}).get("discovery", {})
        detector_rows = "\n".join(
            "<tr>"
            f"<td>{escape(str(d.get('name', 'unknown')))}</td>"
            f"<td>{escape(str(d.get('findings', 0)))}</td>"
            f"<td>{escape('error' if d.get('error') else 'ok')}</td>"
            f"<td>{escape(str(d.get('duration_ms', 0)))}</td>"
            "</tr>"
            for d in (stats or {}).get("detectors", [])
        )

        html = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>bb_scanner_v2 Report - {escape(target_url)}</title>
    <style>
        body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1b1f23; }}
        h1, h2 {{ margin-bottom: 8px; }}
        .muted {{ color: #586069; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin: 14px 0 22px; }}
        .card {{ border: 1px solid #d0d7de; border-radius: 8px; padding: 10px; background: #f6f8fa; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }}
        th {{ background: #f6f8fa; }}
        code {{ background: #f6f8fa; padding: 1px 4px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>bb_scanner_v2 Report</h1>
    <p><strong>Target URL:</strong> {escape(target_url)}</p>
    <p class="muted"><strong>Authorized use only. Do not scan systems without permission.</strong></p>
    <p class="muted">Generated at: {escape(datetime.now(timezone.utc).isoformat())}</p>

    <div class="grid">
        <div class="card"><strong>Total Findings</strong><br>{len(findings)}</div>
        <div class="card"><strong>Critical</strong><br>{sev_counts['critical']}</div>
        <div class="card"><strong>High</strong><br>{sev_counts['high']}</div>
        <div class="card"><strong>Medium/Low</strong><br>{sev_counts['medium']}/{sev_counts['low']}</div>
    </div>

    <h2>Findings</h2>
    <table>
        <thead>
            <tr><th>Severity</th><th>Vulnerability</th><th>URL</th><th>Parameter</th><th>CWE</th><th>OWASP</th><th>Evidence</th></tr>
        </thead>
        <tbody>
            {findings_rows}
        </tbody>
    </table>

    <h2>Coverage Diagnostics</h2>
    <p>
        URLs discovered: <code>{escape(str(discovery.get('urls', 0)))}</code> |
        Forms: <code>{escape(str(discovery.get('forms', 0)))}</code> |
        JS files: <code>{escape(str(discovery.get('js_files', 0)))}</code>
    </p>
    <table>
        <thead>
            <tr><th>Detector</th><th>Findings</th><th>Status</th><th>Time (ms)</th></tr>
        </thead>
        <tbody>
            {detector_rows or "<tr><td colspan='4'>No detector stats available.</td></tr>"}
        </tbody>
    </table>
</body>
</html>
"""

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return html_path

    @staticmethod
    def exit_code_for_findings(findings: List[Finding]) -> int:
        serious = any(f.severity.lower() in {"critical", "high"} for f in findings)
        return 2 if serious else 0

    @staticmethod
    def _sarif_level(severity: str) -> str:
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        return mapping.get(severity.lower(), "warning")

    def write_sarif_report(self, findings: List[Finding], target_url: str, sarif_path: str) -> str:
        """Emit a SARIF 2.1.0 report for CI / GitHub code scanning ingestion."""
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for finding in findings:
            rule_id = f"{finding.detector}/{finding.vulnerability}".replace(" ", "-")
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": finding.vulnerability.replace(" ", ""),
                    "shortDescription": {"text": finding.vulnerability},
                    "fullDescription": {"text": finding.description},
                    "helpUri": finding.references[0] if finding.references else "https://owasp.org/",
                    "properties": {
                        "cwe": finding.cwe,
                        "owasp": finding.owasp,
                        "security-severity": self._security_severity(finding.severity),
                    },
                    "defaultConfiguration": {"level": self._sarif_level(finding.severity)},
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "level": self._sarif_level(finding.severity),
                    "message": {
                        "text": (
                            f"{finding.vulnerability} ({finding.severity.upper()}) "
                            f"at parameter '{finding.parameter or 'n/a'}'. "
                            f"{finding.description} Evidence: {finding.evidence[:300]}"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.url},
                            }
                        }
                    ],
                    "properties": {
                        "cwe": finding.cwe,
                        "owasp": finding.owasp,
                        "confidence": finding.confidence,
                        "parameter": finding.parameter or "",
                    },
                }
            )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bb_scanner_v2",
                            "informationUri": "https://owasp.org/",
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": results,
                    "properties": {"target": target_url},
                }
            ],
        }

        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        return sarif_path

    @staticmethod
    def _security_severity(severity: str) -> str:
        # Numeric CVSS-like band expected by GitHub code scanning.
        mapping = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
        return mapping.get(severity.lower(), "5.0")
