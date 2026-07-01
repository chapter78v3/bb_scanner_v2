from __future__ import annotations

import os
import time
from typing import Dict, List

from .content_discovery import ContentDiscovery
from .crawler import WebCrawler
from .detectors import DEFAULT_DETECTORS
from .knowledge_base import KnowledgeBase
from .models import Finding, ScanContext
from .nuclei import NucleiRunner
from .oast import build_oast_client
from .registry import DetectorRegistry
from .renderer import JSRenderer
from .request_engine import RequestEngine


class Scanner:
    """Coordinates crawler, detector plugins, and reporting pipeline."""

    def __init__(
        self,
        target_url: str,
        max_pages: int,
        allow_external: bool,
        respect_robots: bool,
        delay_seconds: float,
        timeout_seconds: int,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        seed_urls: List[str] | None = None,
        lfi_aggressive: bool = False,
        lfi_max_payloads: int = 0,
        sqli_aggressive: bool = False,
        sqli_matrix_bypass: bool = False,
        sqli_max_payloads: int = 0,
        sqli_custom_params: List[str] | None = None,
        sqli_time_threshold: float = 2.2,
        sqli_baseline_samples: int = 3,
        sqli_test_samples: int = 3,
        sqli_probe_log_limit: int = 200,
        verify_tls: bool = True,
        proxy: str | None = None,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        concurrency: int = 1,
        render_js: bool = False,
        oast_server: str | None = None,
        oast_interactsh: bool = False,
        headers_b: Dict[str, str] | None = None,
        cookies_b: Dict[str, str] | None = None,
        content_discovery: bool = True,
        wordlist_path: str | None = None,
        discovery_extensions: List[str] | None = None,
        discovery_max_paths: int = 0,
        nuclei: bool = False,
        nuclei_path: str = "nuclei",
        nuclei_templates: List[str] | None = None,
        nuclei_severity: str | None = None,
        nuclei_tags: str | None = None,
        nuclei_rate_limit: int = 150,
        nuclei_concurrency: int = 25,
        nuclei_timeout: int = 5,
        nuclei_overall_timeout: int | None = None,
        knowledge_base_path: str | None = None,
    ) -> None:
        self.target_url = target_url
        self.allow_external = allow_external
        self.respect_robots = respect_robots
        self.seed_urls = [u.strip() for u in (seed_urls or []) if u.strip()]
        self.lfi_aggressive = lfi_aggressive
        self.lfi_max_payloads = max(0, lfi_max_payloads)
        self.sqli_aggressive = sqli_aggressive
        self.sqli_matrix_bypass = sqli_matrix_bypass
        self.sqli_max_payloads = max(0, sqli_max_payloads)
        self.sqli_custom_params = [p.strip() for p in (sqli_custom_params or []) if p.strip()]
        self.sqli_time_threshold = max(0.1, sqli_time_threshold)
        self.sqli_baseline_samples = max(1, sqli_baseline_samples)
        self.sqli_test_samples = max(1, sqli_test_samples)
        self.sqli_probe_log_limit = max(10, sqli_probe_log_limit)
        self.concurrency = max(1, concurrency)
        self.oast_client = build_oast_client(oast_server, use_interactsh=oast_interactsh)
        self.last_run_stats: Dict[str, object] = {}
        self.engine = RequestEngine(
            delay_seconds=delay_seconds,
            timeout_seconds=timeout_seconds,
            headers=headers,
            cookies=cookies,
            verify_tls=verify_tls,
            proxy=proxy,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )
        # Optional second identity for cross-identity access-control (BOLA/IDOR).
        self.secondary_engine = None
        if cookies_b or headers_b:
            self.secondary_engine = RequestEngine(
                delay_seconds=delay_seconds,
                timeout_seconds=timeout_seconds,
                headers=headers_b,
                cookies=cookies_b,
                verify_tls=verify_tls,
                proxy=proxy,
                max_retries=max_retries,
                backoff_factor=backoff_factor,
            )
        self.renderer = JSRenderer() if render_js else None
        self.crawler = WebCrawler(
            request_engine=self.engine,
            max_pages=max_pages,
            allow_external=allow_external,
            respect_robots=respect_robots,
            concurrency=self.concurrency,
            renderer=self.renderer,
        )
        self.registry = DetectorRegistry()
        for detector_cls in DEFAULT_DETECTORS:
            self.registry.register(detector_cls)
        self.content_discovery = None
        if content_discovery:
            self.content_discovery = ContentDiscovery(
                engine=self.engine,
                wordlist_path=wordlist_path,
                extensions=discovery_extensions,
                max_paths=discovery_max_paths,
                concurrency=self.concurrency,
            )
        self.nuclei_runner = None
        if nuclei:
            self.nuclei_runner = NucleiRunner(
                nuclei_path=nuclei_path,
                templates=nuclei_templates,
                severity=nuclei_severity,
                tags=nuclei_tags,
                rate_limit=nuclei_rate_limit,
                concurrency=nuclei_concurrency,
                request_timeout=nuclei_timeout,
                overall_timeout=nuclei_overall_timeout,
                proxy=proxy,
                verify_tls=verify_tls,
                headers=headers,
                cookies=cookies,
            )

        # Institutional memory: prior bug-bounty findings for this target's host.
        # Loaded from an operator-supplied knowledge base so the scanner re-tests
        # known hotspots first and can flag reachable endpoints as regressions.
        self.knowledge_base = None
        self.kb_seed_urls: List[str] = []
        if knowledge_base_path and os.path.isfile(knowledge_base_path):
            try:
                self.knowledge_base = KnowledgeBase.load(knowledge_base_path)
            except (OSError, ValueError):
                self.knowledge_base = None
        if self.knowledge_base is not None:
            self.kb_seed_urls = self.knowledge_base.seed_urls_for(self.target_url)
            for url in self.kb_seed_urls:
                if url not in self.seed_urls:
                    self.seed_urls.append(url)
            for param in self.knowledge_base.param_hints_for(self.target_url):
                if param not in self.sqli_custom_params:
                    self.sqli_custom_params.append(param)

    def run(self) -> List[Finding]:
        preflight = self._preflight()

        # Forced browsing: probe the wordlist for unlinked paths before crawling
        # so any live paths are both crawled and tested by every detector.
        discovery_findings: List[Finding] = []
        discovered_paths: List[str] = []
        if self.content_discovery is not None:
            discovered_paths, discovery_findings = self.content_discovery.discover(self.target_url)
            for path in discovered_paths:
                if path not in self.seed_urls:
                    self.seed_urls.append(path)

        crawl_result = self.crawler.crawl(self.target_url)
        for seed in self.seed_urls:
            if seed not in crawl_result.urls:
                crawl_result.urls.append(seed)
        context = ScanContext(
            target_url=self.target_url,
            crawl=crawl_result,
            allow_external=self.allow_external,
            respect_robots=self.respect_robots,
            authenticated=bool(self.engine.session.cookies),
            lfi_aggressive=self.lfi_aggressive,
            lfi_max_payloads=self.lfi_max_payloads,
            sqli_aggressive=self.sqli_aggressive,
            sqli_matrix_bypass=self.sqli_matrix_bypass,
            sqli_max_payloads=self.sqli_max_payloads,
            sqli_custom_params=self.sqli_custom_params,
            sqli_time_threshold=self.sqli_time_threshold,
            sqli_baseline_samples=self.sqli_baseline_samples,
            sqli_test_samples=self.sqli_test_samples,
            sqli_probe_log_limit=self.sqli_probe_log_limit,
            seed_urls=self.seed_urls,
            oast=self.oast_client,
            secondary_engine=self.secondary_engine,
            renderer=self.renderer,
            metadata={
                "urls_discovered": str(len(crawl_result.urls)),
                "forms_discovered": str(len(crawl_result.forms)),
                "js_files_discovered": str(len(crawl_result.js_files)),
                "seed_urls": ",".join(self.seed_urls),
                "lfi_aggressive": str(self.lfi_aggressive),
                "lfi_max_payloads": str(self.lfi_max_payloads),
                "sqli_aggressive": str(self.sqli_aggressive),
                "sqli_matrix_bypass": str(self.sqli_matrix_bypass),
                "sqli_max_payloads": str(self.sqli_max_payloads),
                "sqli_custom_params": ",".join(self.sqli_custom_params),
                "sqli_time_threshold": str(self.sqli_time_threshold),
                "sqli_baseline_samples": str(self.sqli_baseline_samples),
                "sqli_test_samples": str(self.sqli_test_samples),
                "sqli_probe_log_limit": str(self.sqli_probe_log_limit),
            },
        )

        findings: List[Finding] = list(discovery_findings)
        detector_stats: List[Dict[str, object]] = []
        for detector in self.registry.create_all():
            started = time.monotonic()
            before = len(findings)
            detector_error = ""
            try:
                findings.extend(detector.run(context, self.engine))
            except Exception as exc:
                detector_error = str(exc)
                findings.append(
                    Finding(
                        vulnerability="Scanner Detector Error",
                        severity="low",
                        cwe="CWE-703",
                        owasp="A09:2021 Security Logging and Monitoring Failures",
                        url=self.target_url,
                        parameter=None,
                        description=f"Detector '{detector.name}' failed during execution.",
                        evidence=str(exc),
                        detector=detector.name,
                        confidence="high",
                    )
                )
            detector_stats.append(
                {
                    "name": detector.name,
                    "findings": len(findings) - before,
                    "error": detector_error,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
            )

        # Poll the OAST collaborator for out-of-band interactions and confirm
        # any blind findings (e.g. blind SSRF) that produced a real callback.
        oast_interactions = self._correlate_oast(findings)

        # Template-driven scanning (CVEs, misconfigurations, exposed panels)
        # over everything discovered, merged into the same findings pipeline.
        nuclei_stats: Dict[str, object] = {"enabled": self.nuclei_runner is not None}
        if self.nuclei_runner is not None:
            nuclei_targets = list(dict.fromkeys(crawl_result.urls))
            nuclei_findings, nuclei_stats = self.nuclei_runner.scan(nuclei_targets)
            findings.extend(nuclei_findings)

        # Regression watch: flag historically-vulnerable endpoints that are still
        # reachable so the operator confirms the original fix has not regressed.
        kb_stats: Dict[str, object] = {"enabled": self.knowledge_base is not None}
        if self.knowledge_base is not None:
            reachable = set(crawl_result.urls)
            regression_findings = self.knowledge_base.regression_findings(self.target_url, reachable)
            findings.extend(regression_findings)
            kb_stats = {
                "enabled": True,
                "host_findings": len(self.knowledge_base.for_target(self.target_url)),
                "seed_urls_added": len(self.kb_seed_urls),
                "regressions_flagged": len(regression_findings),
            }

        self.last_run_stats = {
            "discovery": {
                "urls": len(crawl_result.urls),
                "forms": len(crawl_result.forms),
                "js_files": len(crawl_result.js_files),
                "pages_fetched": len(crawl_result.observations),
                "fetch_errors": len(crawl_result.errors),
                "sample_urls": crawl_result.urls[:20],
                "sample_form_actions": [f.action_url for f in crawl_result.forms[:20]],
                "sample_js_files": crawl_result.js_files[:20],
                "sample_errors": crawl_result.errors[:20],
            },
            "detectors": detector_stats,
            "content_discovery": {
                "enabled": self.content_discovery is not None,
                "paths_discovered": len(discovered_paths),
                "sensitive_findings": len(discovery_findings),
                "sample_paths": discovered_paths[:20],
            },
            "sqli_probes": context.metadata.get("sqli_probe_artifacts", []),
            "oast_interactions": oast_interactions,
            "nuclei": nuclei_stats,
            "knowledge_base": kb_stats,
            "preflight": preflight,
            "configuration": {
                "seed_urls": self.seed_urls,
                "lfi_aggressive": self.lfi_aggressive,
                "lfi_max_payloads": self.lfi_max_payloads,
                "sqli_aggressive": self.sqli_aggressive,
                "sqli_matrix_bypass": self.sqli_matrix_bypass,
                "sqli_max_payloads": self.sqli_max_payloads,
                "sqli_custom_params": self.sqli_custom_params,
                "sqli_time_threshold": self.sqli_time_threshold,
                "sqli_baseline_samples": self.sqli_baseline_samples,
                "sqli_test_samples": self.sqli_test_samples,
                "sqli_probe_log_limit": self.sqli_probe_log_limit,
                "respect_robots": self.respect_robots,
                "allow_external": self.allow_external,
            },
        }

        return findings

    def _preflight(self) -> Dict[str, object]:
        """Fetch the target once before crawling and print its status/headers.

        Gives immediate feedback on reachability, TLS, redirects, and key
        security headers so the operator knows the scan context up front.
        """
        print("\n=== Pre-flight ===")
        print(f"GET {self.target_url}")
        info: Dict[str, object] = {"url": self.target_url}
        try:
            response = self.engine.get(self.target_url)
        except Exception as exc:
            info["error_type"] = type(exc).__name__
            info["error"] = str(exc)[:300]
            print(f"  FAILED: {type(exc).__name__}: {str(exc)[:200]}")
            if "SSL" in type(exc).__name__ or "CERTIFICATE" in str(exc).upper():
                print("  Hint: TLS verification failed. If you trust this host, re-run with --insecure.")
            print("  Continuing to crawl anyway...")
            return info

        info["status_code"] = response.status_code
        info["final_url"] = response.url
        info["content_type"] = response.headers.get("Content-Type", "")
        info["server"] = response.headers.get("Server", "")
        redirected = response.url != self.target_url

        print(f"  Status: {response.status_code}  Content-Type: {info['content_type'] or 'n/a'}")
        if redirected:
            print(f"  Redirected to: {response.url}")
        if info["server"]:
            print(f"  Server: {info['server']}")

        interesting = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Set-Cookie",
            "Access-Control-Allow-Origin",
            "WWW-Authenticate",
        ]
        present = {h: response.headers[h] for h in interesting if h in response.headers}
        info["security_headers_present"] = list(present.keys())
        info["security_headers_missing"] = [h for h in interesting[:4] if h not in response.headers]
        print("  Security headers present: " + (", ".join(present.keys()) if present else "none"))
        if info["security_headers_missing"]:
            print("  Notable missing headers: " + ", ".join(info["security_headers_missing"]))
        if response.status_code in (401, 403):
            print("  Note: target requires authorization. Provide --cookie/--header for authenticated scanning.")

        return info

    def _correlate_oast(self, findings: List[Finding]) -> List[Dict[str, object]]:
        """Poll the OAST client and upgrade blind probes to confirmed findings."""
        client = self.oast_client
        if client is None or not getattr(client, "enabled", False):
            return []
        try:
            interactions = client.poll()
        except Exception:
            return []

        recorded: List[Dict[str, object]] = []
        for interaction in interactions:
            recorded.append(
                {
                    "correlation": interaction.correlation_id,
                    "protocol": interaction.protocol,
                    "remote_address": interaction.remote_address,
                }
            )
            findings.append(
                Finding(
                    vulnerability="Blind SSRF Confirmed via OAST",
                    severity="high",
                    cwe="CWE-918",
                    owasp="A10:2021 SSRF",
                    url=self.target_url,
                    parameter=None,
                    description=(
                        "An out-of-band interaction was received on the collaborator, confirming "
                        "server-side request egress triggered by an injected callback payload."
                    ),
                    evidence=(
                        f"protocol={interaction.protocol}; source={interaction.remote_address}; "
                        f"correlation={interaction.correlation_id}"
                    ),
                    detector="oast",
                    confidence="high",
                    references=["https://portswigger.net/web-security/ssrf/blind"],
                )
            )
        return recorded
