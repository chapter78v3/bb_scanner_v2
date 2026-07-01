from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Finding

# Severity values Nuclei emits, normalized to the scanner's own scale.
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class NucleiRunner:
    """Runs ProjectDiscovery's `nuclei` over discovered URLs and adapts its
    JSONL output into the scanner's `Finding` model.

    Degrades gracefully: if the `nuclei` binary is not installed, `scan()`
    returns no findings and reports that it was skipped, so the rest of the
    pipeline is unaffected.
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates: Optional[List[str]] = None,
        severity: Optional[str] = None,
        tags: Optional[str] = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        request_timeout: int = 5,
        overall_timeout: Optional[int] = None,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.nuclei_path = nuclei_path or "nuclei"
        self.templates = [t for t in (templates or []) if t]
        self.severity = severity
        self.tags = tags
        self.rate_limit = max(1, rate_limit)
        self.concurrency = max(1, concurrency)
        self.request_timeout = max(1, request_timeout)
        self.overall_timeout = overall_timeout
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.headers = headers or {}
        self.cookies = cookies or {}

    def is_available(self) -> bool:
        return shutil.which(self.nuclei_path) is not None

    def _build_command(self, targets_file: str) -> List[str]:
        cmd = [
            self.nuclei_path,
            "-list", targets_file,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-no-color",
            "-rate-limit", str(self.rate_limit),
            "-concurrency", str(self.concurrency),
            "-timeout", str(self.request_timeout),
        ]
        for template in self.templates:
            cmd += ["-templates", template]
        if self.severity:
            cmd += ["-severity", self.severity]
        if self.tags:
            cmd += ["-tags", self.tags]
        if self.proxy:
            cmd += ["-proxy", self.proxy]
        # Pass auth context so Nuclei tests the same session the scanner used.
        for name, value in self.headers.items():
            cmd += ["-header", f"{name}: {value}"]
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            cmd += ["-header", f"Cookie: {cookie_str}"]
        return cmd

    def scan(self, urls: List[str]) -> Tuple[List[Finding], Dict[str, object]]:
        stats: Dict[str, object] = {
            "enabled": True,
            "available": self.is_available(),
            "targets": len(urls),
            "templates_matched": 0,
            "runtime_ms": 0,
        }

        print("\n=== Nuclei ===")
        if not urls:
            print("  No targets to scan; skipping.")
            stats["skipped_reason"] = "no_targets"
            return [], stats
        if not self.is_available():
            print(f"  '{self.nuclei_path}' not found on PATH; skipping. Install from "
                  "https://github.com/projectdiscovery/nuclei to enable this stage.")
            stats["skipped_reason"] = "binary_not_found"
            return [], stats

        # Unique targets, order preserved, written to a temp list file so URLs
        # never touch the shell (no shell=True, no argument injection).
        unique = list(dict.fromkeys(u for u in urls if u))
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        try:
            tmp.write("\n".join(unique))
            tmp.flush()
            tmp.close()

            cmd = self._build_command(tmp.name)
            print(f"  Running nuclei over {len(unique)} target(s)...")
            started = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.overall_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                print(f"  nuclei timed out after {self.overall_timeout}s; partial results discarded.")
                stats["skipped_reason"] = "timeout"
                stats["runtime_ms"] = int((time.monotonic() - started) * 1000)
                return [], stats
            except Exception as exc:  # pragma: no cover - environment dependent
                print(f"  Failed to run nuclei: {exc}")
                stats["skipped_reason"] = f"error: {exc}"
                return [], stats

            stats["runtime_ms"] = int((time.monotonic() - started) * 1000)
            findings = self._parse_output(proc.stdout)
            stats["templates_matched"] = len(findings)
            print(f"  nuclei produced {len(findings)} finding(s).")
            if proc.returncode != 0 and not findings and proc.stderr.strip():
                print(f"  nuclei stderr: {proc.stderr.strip()[:300]}")
            return findings, stats
        finally:
            try:
                Path(tmp.name).unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_output(self, stdout: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = self._to_finding(record)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _normalize_severity(value: str) -> str:
        sev = (value or "").strip().lower()
        return sev if sev in _ALLOWED_SEVERITIES else "info"

    def _to_finding(self, record: Dict[str, object]) -> Optional[Finding]:
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        template_id = str(record.get("template-id") or record.get("templateID") or "nuclei")
        name = str(info.get("name") or template_id)
        severity = self._normalize_severity(str(info.get("severity") or "info"))

        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwe = self._first(classification.get("cwe-id"))
        cve = self._first(classification.get("cve-id"))

        url = str(record.get("matched-at") or record.get("host") or record.get("url") or "")
        matcher = record.get("matcher-name")
        extracted = record.get("extracted-results")

        evidence_parts = [f"template={template_id}"]
        if matcher:
            evidence_parts.append(f"matcher={matcher}")
        if cve:
            evidence_parts.append(f"cve={cve}")
        if isinstance(extracted, list) and extracted:
            evidence_parts.append("extracted=" + ", ".join(str(e) for e in extracted[:5]))
        evidence = "; ".join(evidence_parts)

        references: List[str] = []
        ref = info.get("reference")
        if isinstance(ref, list):
            references = [str(r) for r in ref if r]
        elif isinstance(ref, str) and ref:
            references = [ref]
        if cve:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        description = str(info.get("description") or name)

        return Finding(
            vulnerability=name,
            severity=severity,
            cwe=cwe or "CWE-1035",
            owasp="A06:2021 Vulnerable and Outdated Components",
            url=url,
            parameter=None,
            description=description,
            evidence=evidence,
            detector="nuclei",
            confidence="high",
            references=references,
        )

    @staticmethod
    def _first(value: object) -> str:
        if isinstance(value, list) and value:
            return str(value[0])
        if isinstance(value, str):
            return value
        return ""
