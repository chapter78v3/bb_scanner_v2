from __future__ import annotations

import argparse
from typing import Dict, List

from .reporting import ReportingEngine
from .scanner import Scanner


def parse_key_value(items: List[str], separator: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for item in items:
        if separator not in item:
            continue
        key, value = item.split(separator, 1)
        parsed[key.strip()] = value.strip()
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "bb_scanner_v2 - Modular web vulnerability scanner. "
            "Authorized use only. Do not scan systems without permission."
        )
    )
    parser.add_argument("--url", required=True, help="Target root URL.")
    parser.add_argument("--max-pages", type=int, default=30, help="Maximum pages to crawl.")
    parser.add_argument("--allow-external", action="store_true", help="Allow off-domain crawling.")
    parser.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt.")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests in seconds.")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds.")
    parser.add_argument("--output", default="report.json", help="Path to JSON report output.")
    parser.add_argument("--cookie", action="append", default=[], help="Cookie in name=value format.")
    parser.add_argument("--header", action="append", default=[], help="Header in Name: value format.")
    parser.add_argument(
        "--seed-url",
        action="append",
        default=[],
        help="Repeatable URL that is tested even if crawler misses it.",
    )
    parser.add_argument(
        "--lfi-aggressive",
        action="store_true",
        help="Probe all parameters for LFI instead of only file/path-like parameter names.",
    )
    parser.add_argument(
        "--lfi-max-payloads",
        type=int,
        default=0,
        help="Cap LFI payloads per parameter. 0 means use all payloads.",
    )
    parser.add_argument(
        "--sqli-aggressive",
        action="store_true",
        help="Probe SQLi on guessed parameters even when target URL has no query string.",
    )
    parser.add_argument(
        "--sqli-matrix-bypass",
        action="store_true",
        help="Also test matrix path variant ;.css; for SQLi probes on each discovered URL.",
    )
    parser.add_argument(
        "--sqli-max-payloads",
        type=int,
        default=0,
        help="Cap SQLi error/time payloads per parameter. 0 means use all payloads.",
    )
    parser.add_argument(
        "--sqli-param",
        action="append",
        default=[],
        help="Repeatable explicit SQLi parameter name (e.g., custOrdId).",
    )
    parser.add_argument(
        "--sqli-time-threshold",
        type=float,
        default=2.2,
        help="Minimum timing delta in seconds to flag SQLi timing signals.",
    )
    parser.add_argument(
        "--sqli-baseline-samples",
        type=int,
        default=3,
        help="Number of baseline timing samples per URL.",
    )
    parser.add_argument(
        "--sqli-test-samples",
        type=int,
        default=3,
        help="Number of timing samples per SQLi probe.",
    )
    parser.add_argument(
        "--sqli-probe-log-limit",
        type=int,
        default=200,
        help="Maximum number of SQLi probe artifacts stored in report coverage.",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification.")
    parser.add_argument(
        "--proxy",
        default=None,
        help="Route all traffic through an HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080 for Burp/ZAP).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=2,
        help="Retries for connection errors and 429/503 responses.",
    )
    parser.add_argument(
        "--backoff-factor",
        type=float,
        default=0.5,
        help="Base seconds for exponential backoff between retries.",
    )
    parser.add_argument(
        "--sarif-output",
        default="report.sarif",
        help="Path to SARIF 2.1.0 report output for CI / code scanning.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Number of pages to fetch in parallel during crawling (rate limit is still enforced).",
    )
    parser.add_argument(
        "--render-js",
        action="store_true",
        help="Render pages with headless Chromium (requires Playwright) to crawl SPA/JS content.",
    )
    parser.add_argument(
        "--oast-server",
        default=None,
        help="Base callback domain for out-of-band (blind SSRF) probes, e.g. yourid.oast.site.",
    )
    parser.add_argument(
        "--oast-interactsh",
        action="store_true",
        help="Use an interactsh server (--oast-server, default oast.pro) with automated polling/correlation.",
    )
    parser.add_argument(
        "--cookie-b",
        action="append",
        default=[],
        help="Second-identity cookie (name=value) for cross-identity IDOR/BOLA testing.",
    )
    parser.add_argument(
        "--header-b",
        action="append",
        default=[],
        help="Second-identity header (Name: value) for cross-identity IDOR/BOLA testing.",
    )
    parser.add_argument(
        "--no-content-discovery",
        action="store_true",
        help="Disable wordlist-based directory/content discovery (enabled by default).",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Path to a custom content-discovery wordlist (defaults to wordlists/content_discovery.txt).",
    )
    parser.add_argument(
        "--discovery-extension",
        action="append",
        default=[],
        help="Repeatable extension appended to file-like wordlist entries (e.g. php, bak, zip).",
    )
    parser.add_argument(
        "--discovery-max-paths",
        type=int,
        default=0,
        help="Cap the number of content-discovery paths probed. 0 means use the whole wordlist.",
    )
    parser.add_argument(
        "--nuclei",
        action="store_true",
        help="Run ProjectDiscovery nuclei over discovered URLs and merge its findings (requires nuclei on PATH).",
    )
    parser.add_argument(
        "--nuclei-path",
        default="nuclei",
        help="Path to the nuclei binary (default: 'nuclei' on PATH).",
    )
    parser.add_argument(
        "--nuclei-templates",
        action="append",
        default=[],
        help="Repeatable template/dir/workflow path passed to nuclei -templates.",
    )
    parser.add_argument(
        "--nuclei-severity",
        default=None,
        help="Comma-separated severities for nuclei (e.g. critical,high,medium).",
    )
    parser.add_argument(
        "--nuclei-tags",
        default=None,
        help="Comma-separated tags to filter nuclei templates (e.g. cve,exposure).",
    )
    parser.add_argument(
        "--nuclei-rate-limit",
        type=int,
        default=150,
        help="Max requests per second for nuclei.",
    )
    parser.add_argument(
        "--nuclei-concurrency",
        type=int,
        default=25,
        help="Number of templates executed in parallel by nuclei.",
    )
    parser.add_argument(
        "--nuclei-timeout",
        type=int,
        default=5,
        help="Per-request timeout in seconds for nuclei.",
    )
    parser.add_argument(
        "--nuclei-overall-timeout",
        type=int,
        default=None,
        help="Optional hard cap in seconds for the entire nuclei run.",
    )
    parser.add_argument(
        "--knowledge-base",
        default="knowledge_base.json",
        help="Path to the historical bug-bounty knowledge base JSON. Used when present to "
             "re-test known hotspots for the target host and flag regressions. "
             "Build it with 'python -m scanner.ingest_reports'.",
    )
    parser.add_argument(
        "--no-knowledge-base",
        action="store_true",
        help="Disable loading the historical knowledge base even if the file exists.",
    )
    parser.add_argument(
        "--kb-generalize",
        action="store_true",
        help="Apply host-agnostic patterns (paths and parameters) learned from ALL historical "
             "findings to the current target, even if its host is not in the knowledge base.",
    )
    parser.add_argument(
        "--kb-learn",
        action="store_true",
        help="Self-learning loop: fold this scan's confirmed (non-informational, "
             "medium/high-confidence) findings back into the knowledge base so future scans "
             "start smarter. Creates the knowledge base file if it does not exist yet.",
    )
    parser.add_argument(
        "--subdomain-discovery",
        action="store_true",
        help="Enumerate subdomains of the target's registrable domain (Certificate "
             "Transparency + DNS brute force) and add discovered hosts as scan seeds. "
             "Dramatically improves subdomain-takeover coverage.",
    )
    parser.add_argument(
        "--subdomain-wordlist",
        default=None,
        help="Optional extra wordlist of subdomain labels (one per line) appended to the "
             "built-in list for the DNS brute-force phase.",
    )
    parser.add_argument(
        "--subdomain-max",
        type=int,
        default=300,
        help="Maximum number of discovered subdomains to seed into the scan (default: 300).",
    )
    parser.add_argument(
        "--subdomain-concurrency",
        type=int,
        default=20,
        help="Concurrent DNS resolutions during subdomain discovery (default: 20).",
    )
    parser.add_argument(
        "--no-subdomain-ct",
        action="store_true",
        help="Skip the Certificate Transparency (crt.sh) source during subdomain discovery.",
    )
    parser.add_argument(
        "--no-subdomain-bruteforce",
        action="store_true",
        help="Skip the DNS brute-force phase during subdomain discovery (use CT logs only).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    cookies = parse_key_value(args.cookie, "=")
    headers = parse_key_value(args.header, ":")
    cookies_b = parse_key_value(args.cookie_b, "=")
    headers_b = parse_key_value(args.header_b, ":")

    print("Authorized use only. Do not scan systems without permission.")
    print(f"Target: {args.url}")

    scanner = Scanner(
        target_url=args.url,
        max_pages=args.max_pages,
        allow_external=args.allow_external,
        respect_robots=not args.ignore_robots,
        delay_seconds=args.delay,
        timeout_seconds=args.timeout,
        headers=headers,
        cookies=cookies,
        seed_urls=args.seed_url,
        lfi_aggressive=args.lfi_aggressive,
        lfi_max_payloads=args.lfi_max_payloads,
        sqli_aggressive=args.sqli_aggressive,
        sqli_matrix_bypass=args.sqli_matrix_bypass,
        sqli_max_payloads=args.sqli_max_payloads,
        sqli_custom_params=args.sqli_param,
        sqli_time_threshold=args.sqli_time_threshold,
        sqli_baseline_samples=args.sqli_baseline_samples,
        sqli_test_samples=args.sqli_test_samples,
        sqli_probe_log_limit=args.sqli_probe_log_limit,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        max_retries=args.max_retries,
        backoff_factor=args.backoff_factor,
        concurrency=args.concurrency,
        render_js=args.render_js,
        oast_server=args.oast_server,
        oast_interactsh=args.oast_interactsh,
        headers_b=headers_b,
        cookies_b=cookies_b,
        content_discovery=not args.no_content_discovery,
        wordlist_path=args.wordlist,
        discovery_extensions=args.discovery_extension,
        discovery_max_paths=args.discovery_max_paths,
        nuclei=args.nuclei,
        nuclei_path=args.nuclei_path,
        nuclei_templates=args.nuclei_templates,
        nuclei_severity=args.nuclei_severity,
        nuclei_tags=args.nuclei_tags,
        nuclei_rate_limit=args.nuclei_rate_limit,
        nuclei_concurrency=args.nuclei_concurrency,
        nuclei_timeout=args.nuclei_timeout,
        nuclei_overall_timeout=args.nuclei_overall_timeout,
        knowledge_base_path=None if args.no_knowledge_base else args.knowledge_base,
        kb_generalize=args.kb_generalize,
        kb_learn=args.kb_learn,
        subdomain_discovery=args.subdomain_discovery,
        subdomain_wordlist=args.subdomain_wordlist,
        subdomain_max=args.subdomain_max,
        subdomain_concurrency=args.subdomain_concurrency,
        subdomain_ct=not args.no_subdomain_ct,
        subdomain_bruteforce=not args.no_subdomain_bruteforce,
    )

    findings = scanner.run()

    reporter = ReportingEngine(output_path=args.output)
    reporter.summarize_console(findings, stats=scanner.last_run_stats)
    reporter.write_json_report(findings=findings, target_url=args.url, stats=scanner.last_run_stats)
    html_path = reporter.write_html_report(findings=findings, target_url=args.url, stats=scanner.last_run_stats)
    sarif_path = reporter.write_sarif_report(findings=findings, target_url=args.url, sarif_path=args.sarif_output)

    code = reporter.exit_code_for_findings(findings)
    print(f"\nReport written to: {args.output}")
    print(f"HTML report written to: {html_path}")
    print(f"SARIF report written to: {sarif_path}")
    print(f"Exit code: {code}")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        raise SystemExit(130)
    except Exception as exc:
        print(f"Scanner failed: {exc}")
        raise SystemExit(3)
