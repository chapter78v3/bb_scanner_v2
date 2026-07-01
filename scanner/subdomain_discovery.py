"""Passive + active subdomain discovery.

Expands the scan's attack surface by enumerating subdomains of the target's
registrable domain, then feeds the results back into the pipeline as seed URLs.
This is what turns the subdomain-takeover detector from "checks the one host you
gave it" into "checks every forgotten subdomain" — where takeovers actually hide.

Two key-free techniques are combined:

* **Certificate Transparency** (crt.sh): every publicly-trusted TLS certificate is
  logged, so querying CT reveals hostnames — including stale ones that no longer
  resolve, which are prime dangling-DNS / takeover candidates.
* **DNS brute force**: a wordlist of common subdomain labels is resolved
  concurrently to surface live hosts that never appeared in a certificate.

Only hosts worth probing are returned as seeds: every CT-sourced host (real,
certificate-backed, and worth a dangling-DNS check even if it no longer resolves)
plus any brute-forced host that actually resolves.
"""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import quote, urlsplit

from .request_engine import RequestEngine

# Optional external wordlist; a compact built-in list is always used as a base.
DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"

# Multi-label public suffixes needed to derive the registrable domain correctly
# (e.g. example.co.uk -> example.co.uk, not co.uk). Not exhaustive, but covers
# the suffixes seen most often in scope.
_MULTI_SUFFIXES = (
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au", "org.au",
    "com.br", "com.mx", "com.ar", "co.in", "co.za", "com.sg", "com.tr", "co.kr",
)

# Compact, high-signal default label list. Extended by --subdomain-wordlist.
_BUILTIN_LABELS = (
    "www", "api", "dev", "staging", "stage", "test", "qa", "uat", "prod", "beta",
    "admin", "portal", "app", "apps", "mobile", "m", "secure", "vpn", "remote",
    "mail", "smtp", "imap", "pop", "webmail", "email", "exchange", "autodiscover",
    "ns1", "ns2", "dns", "mx", "cdn", "static", "assets", "img", "images", "media",
    "files", "download", "downloads", "docs", "support", "help", "status", "blog",
    "shop", "store", "checkout", "pay", "payment", "payments", "billing", "account",
    "accounts", "auth", "login", "sso", "id", "identity", "oauth", "gateway", "gw",
    "internal", "intranet", "corp", "partner", "partners", "vendor", "b2b", "api2",
    "api-dev", "api-staging", "api-test", "dev-api", "staging-api", "test-api",
    "jenkins", "gitlab", "git", "jira", "confluence", "wiki", "grafana", "kibana",
    "prometheus", "vault", "consul", "k8s", "kube", "docker", "registry", "harbor",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic",
    "backup", "old", "new", "legacy", "demo", "sandbox", "preview", "preprod",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "bucket", "data", "analytics",
    "metrics", "logs", "log", "monitor", "monitoring", "alert", "alerts", "ci",
    "cd", "build", "deploy", "release", "artifacts", "nexus", "npm", "pypi",
    "ftp", "sftp", "ssh", "proxy", "lb", "edge", "origin", "www2", "web", "web1",
    "customer", "customers", "client", "clients", "user", "users", "my", "dashboard",
)


@dataclass
class SubdomainResult:
    apex: str = ""
    seed_hosts: List[str] = field(default_factory=list)
    resolved_hosts: List[str] = field(default_factory=list)
    ct_count: int = 0
    brute_count: int = 0
    errors: List[str] = field(default_factory=list)


class SubdomainDiscovery:
    """Enumerate subdomains of a target's registrable domain (no API keys)."""

    def __init__(
        self,
        engine: RequestEngine,
        wordlist_path: Optional[str] = None,
        max_subdomains: int = 300,
        concurrency: int = 20,
        use_ct: bool = True,
        use_bruteforce: bool = True,
    ) -> None:
        self.engine = engine
        self.wordlist_path = wordlist_path
        self.max_subdomains = max(1, max_subdomains)
        self.concurrency = max(1, concurrency)
        self.use_ct = use_ct
        self.use_bruteforce = use_bruteforce

    # -- public API -----------------------------------------------------------
    def discover(self, target_url: str) -> SubdomainResult:
        host = (urlsplit(target_url if "://" in target_url else "https://" + target_url).hostname or "").lower()
        result = SubdomainResult()
        if not host:
            return result
        apex = self._registrable_domain(host)
        result.apex = apex

        candidates: Set[str] = {host}
        ct_hosts: Set[str] = set()
        if self.use_ct:
            try:
                ct_hosts = self._from_ct(apex)
            except Exception as exc:  # network/parse issues must not abort the scan
                result.errors.append(f"ct:{type(exc).__name__}")
            candidates |= ct_hosts
        result.ct_count = len(ct_hosts)

        brute_candidates: Set[str] = set()
        if self.use_bruteforce:
            brute_candidates = {f"{label}.{apex}" for label in self._labels()}

        # Resolve every candidate (CT + brute) concurrently to learn what is live.
        to_resolve = sorted(candidates | brute_candidates)
        resolved = self._resolve_many(to_resolve)
        result.resolved_hosts = sorted(resolved)
        result.brute_count = len({h for h in brute_candidates if h in resolved})

        # Seeds: every CT host (worth a dangling-DNS check even if now NXDOMAIN)
        # plus any brute-forced host that actually resolves. Never seed a random
        # non-resolving wordlist guess.
        seeds: Set[str] = set(ct_hosts)
        seeds |= {h for h in brute_candidates if h in resolved}
        seeds.discard(host)  # the primary target is already scanned directly
        result.seed_hosts = sorted(seeds)[: self.max_subdomains]
        return result

    # -- registrable domain ---------------------------------------------------
    @staticmethod
    def _registrable_domain(host: str) -> str:
        labels = host.split(".")
        if len(labels) <= 2:
            return host
        last_two = ".".join(labels[-2:])
        last_three = ".".join(labels[-3:])
        if last_two in _MULTI_SUFFIXES and len(labels) >= 3:
            return last_three
        return last_two

    # -- certificate transparency --------------------------------------------
    def _from_ct(self, apex: str) -> Set[str]:
        url = f"https://crt.sh/?q={quote('%.' + apex)}&output=json"
        response = self.engine.get(url)
        if response.status_code != 200 or not response.text.strip():
            return set()
        try:
            entries = json.loads(response.text)
        except json.JSONDecodeError:
            return set()
        hosts: Set[str] = set()
        for entry in entries:
            name_value = str(entry.get("name_value", ""))
            for raw in name_value.replace("\r", "\n").split("\n"):
                candidate = raw.strip().lower().lstrip("*.")
                if candidate and self._in_scope(candidate, apex):
                    hosts.add(candidate)
        return hosts

    @staticmethod
    def _in_scope(host: str, apex: str) -> bool:
        return (host == apex or host.endswith("." + apex)) and " " not in host and "@" not in host

    # -- brute force ----------------------------------------------------------
    def _labels(self) -> List[str]:
        labels = list(_BUILTIN_LABELS)
        path = self.wordlist_path or (str(DEFAULT_WORDLIST) if DEFAULT_WORDLIST.is_file() else None)
        if path and Path(path).is_file():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        token = line.strip().lower()
                        if token and not token.startswith("#"):
                            labels.append(token)
            except OSError:
                pass
        # Preserve order while de-duplicating.
        seen: Set[str] = set()
        ordered: List[str] = []
        for label in labels:
            if label not in seen:
                seen.add(label)
                ordered.append(label)
        return ordered

    def _resolve_many(self, hosts: List[str]) -> Set[str]:
        resolved: Set[str] = set()
        if not hosts:
            return resolved
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_map = {executor.submit(self._resolves, h): h for h in hosts}
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    if future.result():
                        resolved.add(host)
                except Exception:
                    continue
        return resolved

    @staticmethod
    def _resolves(host: str) -> bool:
        try:
            socket.gethostbyname(host)
            return True
        except (socket.gaierror, OSError):
            return False
