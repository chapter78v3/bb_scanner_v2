from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .models import Finding
from .request_engine import RequestEngine

# Default wordlist shipped with the project. Loaded on every run unless the
# operator points --wordlist at another file.
DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "content_discovery.txt"

# Statuses that mean "definitely not here" and are never treated as a hit.
NOT_FOUND_STATUSES = {404, 410}

# (needle, vulnerability, severity, cwe, owasp, description) — first match wins.
# Only paths whose discovered URL contains one of these needles are reported as
# findings; everything else is simply fed back into the crawl for the detectors.
SENSITIVE_RULES: List[Tuple[str, str, str, str, str, str]] = [
    (".git", "Exposed Git Repository", "high", "CWE-527",
     "A05:2021 Security Misconfiguration",
     "A version-control directory/file is publicly reachable and may leak source code, history, and secrets."),
    (".svn", "Exposed Version Control Directory", "high", "CWE-527",
     "A05:2021 Security Misconfiguration",
     "A Subversion metadata path is publicly reachable and may leak source code and history."),
    (".hg", "Exposed Version Control Directory", "high", "CWE-527",
     "A05:2021 Security Misconfiguration",
     "A Mercurial metadata path is publicly reachable and may leak source code and history."),
    (".env", "Exposed Environment/Secrets File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "An environment file is publicly reachable and commonly contains credentials, API keys, and connection strings."),
    ("wp-config", "Exposed Configuration File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "An application configuration file is publicly reachable and may expose database credentials and secrets."),
    ("appsettings", "Exposed Configuration File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "An application configuration file is publicly reachable and may expose connection strings and secrets."),
    ("application.properties", "Exposed Configuration File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A Spring configuration file is publicly reachable and may expose credentials and secrets."),
    ("web.config", "Exposed Configuration File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "An IIS configuration file is publicly reachable and may expose secrets and internal settings."),
    (".htpasswd", "Exposed Credentials File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "An HTTP auth credentials file is publicly reachable and may expose password hashes."),
    ("credentials", "Exposed Credentials File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A credentials file is publicly reachable and may expose secrets."),
    (".aws", "Exposed Credentials File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "An AWS credentials path is publicly reachable and may expose access keys."),
    ("secrets", "Exposed Secrets File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A secrets file is publicly reachable and may expose sensitive tokens."),
    (".sql", "Exposed Database Backup", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A SQL dump is publicly reachable and may expose the entire database contents."),
    ("backup", "Exposed Backup/Archive File", "high", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A backup or archive is publicly reachable and may expose source code or data."),
    ("heapdump", "Exposed Spring Boot Actuator (Heap Dump)", "high", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "A Spring Boot actuator heap dump is reachable and may leak in-memory secrets, tokens, and credentials."),
    ("actuator", "Exposed Spring Boot Actuator", "medium", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "A Spring Boot actuator endpoint is reachable and may disclose environment, mappings, and internal state."),
    ("jolokia", "Exposed Jolokia/JMX Endpoint", "high", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "A Jolokia endpoint is reachable and may allow JMX enumeration or remote invocation."),
    ("phpinfo", "PHP Info Disclosure", "medium", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "A phpinfo() page is reachable and discloses environment, paths, and configuration details."),
    ("server-status", "Apache server-status Exposure", "medium", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "The Apache server-status page is reachable and discloses active requests and internal details."),
    ("server-info", "Apache server-info Exposure", "medium", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "The Apache server-info page is reachable and discloses server configuration."),
    ("swagger", "Exposed API Documentation/Schema", "low", "CWE-200",
     "A09:2021 Security Logging and Monitoring Failures",
     "An API schema/documentation endpoint is reachable and maps the application's attack surface."),
    ("openapi", "Exposed API Documentation/Schema", "low", "CWE-200",
     "A09:2021 Security Logging and Monitoring Failures",
     "An OpenAPI schema is reachable and maps the application's attack surface."),
    ("api-docs", "Exposed API Documentation/Schema", "low", "CWE-200",
     "A09:2021 Security Logging and Monitoring Failures",
     "An API documentation endpoint is reachable and maps the application's attack surface."),
    ("graphql", "Exposed GraphQL Endpoint", "low", "CWE-200",
     "A05:2021 Security Misconfiguration",
     "A GraphQL endpoint is reachable; verify introspection is disabled and access control is enforced."),
    ("phpmyadmin", "Exposed Database Admin Interface", "medium", "CWE-284",
     "A05:2021 Security Misconfiguration",
     "A database administration interface is reachable and is a high-value target for brute force."),
    ("adminer", "Exposed Database Admin Interface", "medium", "CWE-284",
     "A05:2021 Security Misconfiguration",
     "A database administration interface is reachable and is a high-value target for brute force."),
    (".ds_store", "Exposed .DS_Store Metadata File", "low", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A macOS .DS_Store file is reachable and can leak directory listings and file names."),
    (".idea", "Exposed IDE Project Directory", "low", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A JetBrains .idea directory is reachable and may leak project structure and paths."),
    (".vscode", "Exposed IDE Project Directory", "low", "CWE-538",
     "A05:2021 Security Misconfiguration",
     "A VS Code .vscode directory is reachable and may leak project settings and paths."),
]

# Substrings that indicate a WAF/security-gateway block or challenge page rather
# than the real resource. These frequently ride on an HTTP 200, which is exactly
# what produces false "exposed file" findings.
BLOCK_INDICATORS: Tuple[str, ...] = (
    "access denied",
    "request blocked",
    "your request has been blocked",
    "this request has been blocked",
    "the request was blocked",
    "has been blocked",
    "attention required",
    "web application firewall",
    "blocked by",
    "unusual traffic",
    "incapsula",
    "imperva",
    "sucuri",
    "mod_security",
    "not acceptable",
    "please enable cookies",
    "ray id",
    "support id:",
    "reference #",
    "akamai",
    "our systems have detected",
)

# HTTP header keys that reveal a WAF/CDN in front of the app. Presence alone is
# NOT treated as a block (many benign sites sit behind Cloudflare/Akamai); it is
# only used together with a blocking status code.
WAF_HEADER_KEYS: Tuple[str, ...] = (
    "cf-ray",
    "x-iinfo",
    "x-sucuri-id",
    "x-sucuri-cache",
    "x-akamai-transformed",
    "x-waf-event-info",
)

# Required body signatures for endpoints whose exposure can be content-verified.
# When a rule has signatures and none appear in the response body, the hit is
# treated as unconfirmed (no finding) to avoid block-page / soft-shell false
# positives. Keyed by the vulnerability name emitted by SENSITIVE_RULES.
CONTENT_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    "PHP Info Disclosure": ("phpinfo()", "php version", "<title>phpinfo"),
    "Apache server-status Exposure": ("apache server status", "requests currently being processed", "server uptime"),
    "Apache server-info Exposure": ("apache server information", "server settings", "server root"),
    "Exposed Spring Boot Actuator": ('"_links"', '"status"', '"diskspace"', '"components"'),
    "Exposed API Documentation/Schema": ("swagger", "openapi", '"paths"', "api documentation"),
    "Exposed GraphQL Endpoint": ("graphql", '"data"', '"errors"', "must provide query", "query root type"),
}


class ProbeResult(NamedTuple):
    """Response fingerprint captured for a single forced-browse request."""

    status: int
    length: int
    final_path: str
    body: str            # first 4000 chars, lowercased, for signature/block checks
    waf_header: bool     # a known WAF/CDN header is present


class ContentDiscovery:
    """Wordlist-based forced browsing to find unlinked paths.

    Probes each wordlist entry against the target root, filters soft-404s using
    a random-path baseline, reports sensitive exposures as findings, and returns
    every live URL so the crawler and detectors can process them too.
    """

    def __init__(
        self,
        engine: RequestEngine,
        wordlist_path: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        max_paths: int = 0,
        concurrency: int = 1,
    ) -> None:
        self.engine = engine
        self.wordlist_path = Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST
        self.extensions = [e.strip().lstrip(".") for e in (extensions or []) if e.strip()]
        self.max_paths = max(0, max_paths)
        self.concurrency = max(1, concurrency)

    def load_words(self) -> List[str]:
        try:
            raw = self.wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        words: List[str] = []
        seen = set()
        for line in raw:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            entry = entry.lstrip("/")
            if entry and entry not in seen:
                seen.add(entry)
                words.append(entry)
        return words

    def _candidate_paths(self, words: List[str]) -> List[str]:
        candidates: List[str] = []
        seen = set()
        for word in words:
            variants = [word]
            # Apply user extensions only to file-like (non-directory) entries.
            if self.extensions and not word.endswith("/") and "." not in word.rsplit("/", 1)[-1]:
                variants.extend(f"{word}.{ext}" for ext in self.extensions)
            for variant in variants:
                if variant not in seen:
                    seen.add(variant)
                    candidates.append(variant)
        if self.max_paths and len(candidates) > self.max_paths:
            candidates = candidates[: self.max_paths]
        return candidates

    def _probe(self, url: str) -> Optional[ProbeResult]:
        """Fetch a candidate path and capture its response fingerprint."""
        try:
            response = self.engine.get(url)
        except Exception:
            return None
        final_path = urlparse(response.url).path
        try:
            body = (response.text or "")[:4000].lower()
        except Exception:
            body = ""
        headers_lower = {k.lower() for k in response.headers.keys()}
        server = response.headers.get("Server", "").lower()
        waf_header = (
            any(key in headers_lower for key in WAF_HEADER_KEYS)
            or "cloudflare" in server
            or "sucuri" in server
            or "akamai" in server
        )
        return ProbeResult(
            status=response.status_code,
            length=len(response.content or b""),
            final_path=final_path,
            body=body,
            waf_header=waf_header,
        )

    def _calibrate(self, base: str) -> List[ProbeResult]:
        """Fetch a few random paths to fingerprint the site's not-found response."""
        signatures: List[ProbeResult] = []
        for _ in range(3):
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            probe = self._probe(urljoin(base, f"zz{token}zz"))
            if probe is not None:
                signatures.append(probe)
        return signatures

    @staticmethod
    def _looks_like_not_found(result: ProbeResult, baselines: List[ProbeResult]) -> bool:
        if result.status in NOT_FOUND_STATUSES:
            return True
        for base in baselines:
            if result.status != base.status:
                continue
            # Redirect-style soft-404: missing paths land on the same page
            # (e.g. /login or home) as the random calibration probes did.
            if result.final_path == base.final_path:
                return True
            # Content-style soft-404: a generic 200 body of near-identical size
            # is served at the requested path. Path differs per request, so we
            # fingerprint on the body length instead.
            tolerance = max(64, int(base.length * 0.05))
            if abs(result.length - base.length) <= tolerance:
                return True
        return False

    @staticmethod
    def _is_block_page(result: ProbeResult) -> bool:
        """Detect WAF/security-gateway block or challenge responses."""
        if any(indicator in result.body for indicator in BLOCK_INDICATORS):
            return True
        # A WAF header combined with a typical blocking status is a strong signal;
        # the header alone is not, since benign sites also sit behind CDNs/WAFs.
        if result.waf_header and result.status in (401, 403, 406, 429, 503):
            return True
        return False

    @staticmethod
    def _classify(url: str) -> Optional[Tuple[str, str, str, str, str]]:
        lowered = url.lower()
        for needle, vuln, severity, cwe, owasp, desc in SENSITIVE_RULES:
            if needle in lowered:
                return vuln, severity, cwe, owasp, desc
        return None

    def discover(self, target_url: str) -> Tuple[List[str], List[Finding]]:
        words = self.load_words()
        if not words:
            print("\n=== Content discovery ===")
            print(f"  No wordlist entries loaded from {self.wordlist_path}; skipping.")
            return [], []

        base = target_url if target_url.endswith("/") else target_url + "/"
        candidates = self._candidate_paths(words)

        print("\n=== Content discovery ===")
        print(f"  Wordlist: {self.wordlist_path} ({len(candidates)} paths)")

        baselines = self._calibrate(base)
        if baselines and all(b.status not in NOT_FOUND_STATUSES for b in baselines):
            print(f"  Note: target does not return 404 for missing paths "
                  f"(soft-404 status {baselines[0].status}); filtering by response fingerprint.")

        urls = [urljoin(base, path) for path in candidates]
        if self.concurrency > 1:
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                probed = list(executor.map(self._probe, urls))
        else:
            probed = [self._probe(url) for url in urls]

        discovered: List[str] = []
        findings: List[Finding] = []
        blocked = 0
        for url, result in zip(urls, probed):
            if result is None:
                continue
            if self._looks_like_not_found(result, baselines):
                continue
            # A WAF/challenge page is not a real exposure; skip it entirely so it
            # neither becomes a finding nor floods the crawl queue.
            if self._is_block_page(result):
                blocked += 1
                continue

            discovered.append(url)
            classified = self._classify(url)
            if classified is None:
                continue

            vuln, severity, cwe, owasp, desc = classified
            signatures = CONTENT_SIGNATURES.get(vuln)
            if signatures and not any(sig in result.body for sig in signatures):
                # Path responded but the body is not the expected content
                # (e.g. a block page or generic app shell): do not report.
                continue

            findings.append(
                Finding(
                    vulnerability=vuln,
                    severity=severity,
                    cwe=cwe,
                    owasp=owasp,
                    url=url,
                    parameter=None,
                    description=desc,
                    evidence=(
                        f"HTTP {result.status}; {result.length} bytes returned for forced-browse request"
                        + ("; response body matched expected content signature." if signatures else ".")
                    ),
                    detector="content_discovery",
                    confidence="medium" if result.status in (401, 403) else "high",
                    references=["https://owasp.org/www-community/attacks/Forced_browsing"],
                )
            )

        summary = f"  Discovered {len(discovered)} live path(s); {len(findings)} flagged as sensitive."
        if blocked:
            summary += f" ({blocked} suppressed as WAF/block pages.)"
        print(summary)
        for finding in findings:
            print(f"    [!] {finding.severity.upper():8} {finding.vulnerability} -> {finding.url}")

        return discovered, findings
