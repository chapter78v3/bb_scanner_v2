"""Historical bug-bounty knowledge base.

Parses previously-triaged bug-bounty reports (exported from JIRA as HTML with a
``.doc`` extension) into structured records, then feeds that institutional memory
back into the scanner so known-vulnerable endpoints are re-tested first and any
still-reachable hotspots are flagged as potential regressions.

The raw reports contain sensitive production detail and must never be committed;
only this parsing code and the derived (also git-ignored) ``knowledge_base.json``
live in the repository.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlsplit

from bs4 import BeautifulSoup

from .models import Finding

# Findings the self-learning loop must never fold back into the knowledge base:
# derived/meta records that would create feedback loops or add no signal.
_NON_LEARNABLE_DETECTORS = {"knowledge_base"}
_NON_LEARNABLE_SEVERITIES = {"info"}
_NON_LEARNABLE_VULN_PREFIXES = ("Regression Watch", "Scanner Detector Error", "Blind ")

# Field labels used by the JIRA HTML export (label cell -> value cell).
_TITLE_ID_RE = re.compile(r"\[#?([A-Z]+-\d+)\]")
# A plausible public hostname: dot-separated labels ending in a TLD of 2+ letters.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_URL_LABEL = "Site URL or APP Name, Etc.:"
_WEAKNESS_LABEL = "Weakness:"
_STATUS_LABEL = "Status:"
_LABELS_LABEL = "Labels:"
_REPORTER_NAME_LABEL = "Name:"

# Map a reported weakness to a canonical vulnerability class, CWE, OWASP category,
# and the scanner detector best suited to re-test it. Matching is done by testing
# whether any key (lowercased) is a substring of the reported weakness text, so
# minor wording variations still resolve. First match wins, so order matters.
_WEAKNESS_MAP: List[tuple] = [
    ("sql injection", ("SQL Injection", "CWE-89", "A03:2021 Injection", "sqli")),
    ("insecure direct object", ("Insecure Direct Object Reference", "CWE-639", "A01:2021 Broken Access Control", "idor")),
    ("idor", ("Insecure Direct Object Reference", "CWE-639", "A01:2021 Broken Access Control", "idor")),
    ("improper access control", ("Improper Access Control", "CWE-284", "A01:2021 Broken Access Control", "idor")),
    ("broken access control", ("Improper Access Control", "CWE-284", "A01:2021 Broken Access Control", "idor")),
    ("improper authentication", ("Improper Authentication", "CWE-287", "A07:2021 Identification and Authentication Failures", "passive")),
    ("authentication", ("Improper Authentication", "CWE-287", "A07:2021 Identification and Authentication Failures", "passive")),
    ("hard-coded cryptographic key", ("Use of Hard-coded Cryptographic Key", "CWE-321", "A02:2021 Cryptographic Failures", "secrets_js")),
    ("hard-coded", ("Use of Hard-coded Credentials", "CWE-798", "A07:2021 Identification and Authentication Failures", "secrets_js")),
    ("api key", ("Exposed API Key / Secret", "CWE-798", "A07:2021 Identification and Authentication Failures", "secrets_js")),
    ("secret", ("Exposed Secret", "CWE-200", "A01:2021 Broken Access Control", "secrets_js")),
    ("credential", ("Exposed Credentials", "CWE-522", "A07:2021 Identification and Authentication Failures", "secrets_js")),
    ("cross site scripting", ("Cross-Site Scripting", "CWE-79", "A03:2021 Injection", "xss")),
    ("cross-site scripting", ("Cross-Site Scripting", "CWE-79", "A03:2021 Injection", "xss")),
    ("xss", ("Cross-Site Scripting", "CWE-79", "A03:2021 Injection", "xss")),
    ("cross site request forgery", ("Cross-Site Request Forgery", "CWE-352", "A01:2021 Broken Access Control", "csrf")),
    ("csrf", ("Cross-Site Request Forgery", "CWE-352", "A01:2021 Broken Access Control", "csrf")),
    ("server-side request forgery", ("Server-Side Request Forgery", "CWE-918", "A10:2021 Server-Side Request Forgery", "ssrf")),
    ("server side request forgery", ("Server-Side Request Forgery", "CWE-918", "A10:2021 Server-Side Request Forgery", "ssrf")),
    ("ssrf", ("Server-Side Request Forgery", "CWE-918", "A10:2021 Server-Side Request Forgery", "ssrf")),
    ("resource injection", ("Resource Injection", "CWE-99", "A03:2021 Injection", "ssrf")),
    ("path traversal", ("Path Traversal", "CWE-22", "A01:2021 Broken Access Control", "lfi")),
    ("local file inclusion", ("Local File Inclusion", "CWE-98", "A03:2021 Injection", "lfi")),
    ("file inclusion", ("File Inclusion", "CWE-98", "A03:2021 Injection", "lfi")),
    ("cache poisoning", ("Web Cache Poisoning", "CWE-444", "A04:2021 Insecure Design", "")),
    ("secure design", ("Violation of Secure Design Principles", "CWE-657", "A04:2021 Insecure Design", "")),
    ("insecure design", ("Insecure Design", "CWE-657", "A04:2021 Insecure Design", "")),
    ("information disclosure", ("Information Disclosure", "CWE-200", "A01:2021 Broken Access Control", "passive")),
    ("information exposure", ("Information Disclosure", "CWE-200", "A01:2021 Broken Access Control", "passive")),
    ("pii", ("Sensitive Information Disclosure", "CWE-359", "A01:2021 Broken Access Control", "passive")),
]

_DEFAULT_CLASS = ("Historical Weakness", "CWE-1035", "A06:2021 Vulnerable and Outdated Components", "")


def _classify_weakness(weakness: str) -> tuple:
    text = (weakness or "").lower()
    for needle, mapped in _WEAKNESS_MAP:
        if needle in text:
            return mapped
    return _DEFAULT_CLASS


def _normalize_url(raw: str) -> str:
    """Turn a report's free-form URL/host field into a canonical https URL.

    Returns an empty string when the field does not contain a plausible
    hostname (some reports leave the field blank or with placeholder text).
    """
    value = (raw or "").strip().strip("`").strip("'\"").split()[0] if raw and raw.strip() else ""
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    host = urlsplit(value).hostname or ""
    if not _HOSTNAME_RE.match(host):
        return ""
    return value


@dataclass
class HistoricalFinding:
    """One structured record distilled from a past bug-bounty report."""

    ticket_id: str
    summary: str
    weakness_raw: str
    vulnerability: str
    cwe: str
    owasp: str
    detector: str
    url: str
    host: str
    path: str
    parameters: List[str] = field(default_factory=list)
    status: str = ""
    labels: List[str] = field(default_factory=list)
    reporter: str = ""
    source_file: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "HistoricalFinding":
        return cls(**data)  # type: ignore[arg-type]


def _extract_fields(soup: BeautifulSoup) -> Dict[str, str]:
    """Collapse the JIRA export's two-column tables into a label->value map."""
    fields: Dict[str, str] = {}
    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if len(cells) >= 2:
            label = cells[0].get_text(" ", strip=True)
            if label and label not in fields:
                fields[label] = cells[1].get_text(" ", strip=True)
    return fields


def parse_report(path: str) -> Optional[HistoricalFinding]:
    """Parse a single exported report file into a :class:`HistoricalFinding`."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            soup = BeautifulSoup(handle.read(), "html.parser")
    except OSError:
        return None

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    fields = _extract_fields(soup)

    id_match = _TITLE_ID_RE.search(title)
    ticket_id = id_match.group(1) if id_match else os.path.splitext(os.path.basename(path))[0]

    summary = title
    if "]" in title:
        summary = title.split("]", 1)[1].strip()

    weakness_raw = fields.get(_WEAKNESS_LABEL, "").strip()
    if not weakness_raw:
        # Some reports omit the Weakness field; fall back to the summary text so
        # classification can still attempt a match.
        weakness_raw = summary
    vulnerability, cwe, owasp, detector = _classify_weakness(weakness_raw)

    url = _normalize_url(fields.get(_URL_LABEL, ""))
    split = urlsplit(url) if url else None
    host = split.hostname or "" if split else ""
    path = split.path or "" if split else ""
    params = sorted(parse_qs(split.query).keys()) if split and split.query else []

    labels_raw = fields.get(_LABELS_LABEL, "")
    labels = [lbl.strip() for lbl in labels_raw.split(",") if lbl.strip()]

    return HistoricalFinding(
        ticket_id=ticket_id,
        summary=summary[:300],
        weakness_raw=weakness_raw[:200],
        vulnerability=vulnerability,
        cwe=cwe,
        owasp=owasp,
        detector=detector,
        url=url,
        host=host,
        path=path,
        parameters=params,
        status=fields.get(_STATUS_LABEL, "").strip(),
        labels=labels,
        reporter=fields.get(_REPORTER_NAME_LABEL, "").strip(),
        source_file=os.path.basename(path),
    )


def _hosts_match(hist_host: str, target_host: str) -> bool:
    if not hist_host or not target_host:
        return False
    hist_host = hist_host.lower()
    target_host = target_host.lower()
    if hist_host == target_host:
        return True
    return hist_host.endswith("." + target_host) or target_host.endswith("." + hist_host)


class KnowledgeBase:
    """Collection of historical findings with scanner-facing query helpers."""

    def __init__(self, findings: Optional[List[HistoricalFinding]] = None) -> None:
        self.findings: List[HistoricalFinding] = findings or []

    # -- construction ---------------------------------------------------------
    @classmethod
    def from_reports(cls, reports_dir: str, patterns: Optional[List[str]] = None) -> "KnowledgeBase":
        patterns = patterns or ["*.doc", "*.docx", "*.html", "*.htm"]
        seen: Dict[str, HistoricalFinding] = {}
        for pattern in patterns:
            for path in sorted(glob.glob(os.path.join(reports_dir, pattern))):
                record = parse_report(path)
                if record is not None:
                    seen[record.ticket_id] = record
        return cls(list(seen.values()))

    @classmethod
    def load(cls, json_path: str) -> "KnowledgeBase":
        with open(json_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        records = [HistoricalFinding.from_dict(item) for item in data.get("findings", [])]
        return cls(records)

    def save(self, json_path: str) -> None:
        payload = {
            "version": 1,
            "count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

    # -- queries --------------------------------------------------------------
    def for_target(self, target_url: str) -> List[HistoricalFinding]:
        target_host = urlsplit(target_url if "://" in target_url else "https://" + target_url).hostname or ""
        return [f for f in self.findings if _hosts_match(f.host, target_host)]

    def seed_urls_for(self, target_url: str) -> List[str]:
        urls: List[str] = []
        for finding in self.for_target(target_url):
            if finding.url and finding.url not in urls:
                urls.append(finding.url)
        return urls

    def param_hints_for(self, target_url: str) -> List[str]:
        params: List[str] = []
        for finding in self.for_target(target_url):
            for param in finding.parameters:
                if param not in params:
                    params.append(param)
        return params

    # -- global (host-agnostic) learning -------------------------------------
    def learned_paths(self) -> List[str]:
        """Distinct URL paths seen across ALL historical findings, host-agnostic.

        These are re-probed on any target so a weakness pattern found on one host
        (e.g. ``/portabilidad/device/listAllDevice``) is checked everywhere.
        """
        paths: List[str] = []
        for finding in self.findings:
            path = (finding.path or "").strip()
            if not path or path == "/":
                continue
            normalized = path.lstrip("/").rstrip("&?/")
            if normalized and normalized not in paths:
                paths.append(normalized)
        return paths

    def learned_params(self) -> List[str]:
        """Every parameter name abused across ALL historical findings."""
        params: List[str] = []
        for finding in self.findings:
            for param in finding.parameters:
                if param and param not in params:
                    params.append(param)
        return params

    def learned_path_segments(self, min_length: int = 3) -> List[str]:
        """Individual path segments (tokens) across all findings, for wordlists."""
        segments: List[str] = []
        for finding in self.findings:
            for segment in (finding.path or "").split("/"):
                token = segment.strip().lower()
                if len(token) >= min_length and "." not in token and token not in segments:
                    segments.append(token)
        return segments

    def regression_findings(self, target_url: str, reachable_urls: set) -> List[Finding]:
        """Emit an informational watch for each historical hotspot that is still
        reachable, so the operator confirms the prior fix has not regressed."""
        reachable = {u.split("#", 1)[0].rstrip("/") for u in reachable_urls}
        findings: List[Finding] = []
        for hist in self.for_target(target_url):
            if not hist.url:
                continue
            if hist.url.rstrip("/") not in reachable:
                continue
            findings.append(
                Finding(
                    vulnerability=f"Regression Watch: {hist.vulnerability}",
                    severity="info",
                    cwe=hist.cwe,
                    owasp=hist.owasp,
                    url=hist.url,
                    parameter=hist.parameters[0] if hist.parameters else None,
                    description=(
                        f"This endpoint previously had a reported {hist.vulnerability} "
                        f"({hist.ticket_id}: {hist.summary}). It is reachable in this scan; "
                        "verify the original fix still holds and that no regression was introduced."
                    ),
                    evidence=f"ticket={hist.ticket_id}; weakness={hist.weakness_raw}; status={hist.status or 'n/a'}",
                    detector="knowledge_base",
                    confidence="medium",
                    references=[],
                )
            )
        return findings

    # -- self-learning loop --------------------------------------------------
    @staticmethod
    def _is_learnable(finding: Finding) -> bool:
        """A finding is worth remembering only if it is a concrete, confirmed
        weakness — not an informational note, meta record, or scanner error."""
        if finding.detector in _NON_LEARNABLE_DETECTORS:
            return False
        if (finding.severity or "").lower() in _NON_LEARNABLE_SEVERITIES:
            return False
        if (finding.confidence or "").lower() == "low":
            return False
        vuln = finding.vulnerability or ""
        if any(vuln.startswith(prefix) for prefix in _NON_LEARNABLE_VULN_PREFIXES):
            return False
        return bool(urlsplit(finding.url).hostname)

    @staticmethod
    def _finding_key(host: str, path: str, vulnerability: str, parameter: str) -> str:
        raw = "|".join((host.lower(), path.lower(), vulnerability.lower(), (parameter or "").lower()))
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]

    def _existing_keys(self) -> Set[str]:
        keys: Set[str] = set()
        for hist in self.findings:
            param = hist.parameters[0] if hist.parameters else ""
            keys.add(self._finding_key(hist.host, hist.path, hist.vulnerability, param))
        return keys

    def _to_historical(self, finding: Finding, source: str) -> HistoricalFinding:
        split = urlsplit(finding.url)
        host = split.hostname or ""
        path = split.path or ""
        params = sorted(parse_qs(split.query).keys()) if split.query else []
        if finding.parameter and finding.parameter not in params:
            params.append(finding.parameter)
        key = self._finding_key(host, path, finding.vulnerability, finding.parameter or "")
        return HistoricalFinding(
            ticket_id=f"SCAN-{key}",
            summary=(finding.description or finding.vulnerability)[:300],
            weakness_raw=finding.vulnerability[:200],
            vulnerability=finding.vulnerability,
            cwe=finding.cwe,
            owasp=finding.owasp,
            detector=finding.detector,
            url=finding.url,
            host=host,
            path=path,
            parameters=params,
            status="Confirmed by scanner",
            labels=["auto-learned", (finding.severity or "").lower(), (finding.confidence or "").lower()],
            reporter="bb_scanner",
            source_file=source,
        )

    def learn_from_findings(self, findings: List[Finding], source: Optional[str] = None) -> List[HistoricalFinding]:
        """Fold this scan's confirmed findings back into the knowledge base.

        Only concrete, non-informational, medium/high-confidence findings are
        remembered. Records are deduplicated by (host, path, vulnerability,
        parameter) so re-running a scan never inflates the store. Returns the
        list of *newly* added historical findings.
        """
        source = source or f"scan:{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"
        existing = self._existing_keys()
        added: List[HistoricalFinding] = []
        for finding in findings:
            if not self._is_learnable(finding):
                continue
            split = urlsplit(finding.url)
            key = self._finding_key(split.hostname or "", split.path or "", finding.vulnerability, finding.parameter or "")
            if key in existing:
                continue
            existing.add(key)
            record = self._to_historical(finding, source)
            self.findings.append(record)
            added.append(record)
        return added

    def stats(self) -> Dict[str, object]:
        by_class: Dict[str, int] = {}
        for finding in self.findings:
            by_class[finding.vulnerability] = by_class.get(finding.vulnerability, 0) + 1
        return {
            "total": len(self.findings),
            "by_class": by_class,
            "hosts": sorted({f.host for f in self.findings if f.host}),
        }
