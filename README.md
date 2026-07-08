# bb_scanner_v2

## Authorized Use Only

**Authorized use only. Do not scan systems without permission.**

This project is a modular, non-destructive web application vulnerability scanner designed for security testing of authorized targets.

## Architecture Overview

The scanner is designed around separation of concerns:

1. `crawler.py`
- Discovers in-scope URLs, forms, and JavaScript files.
- Restricts crawling to target domain by default.
- Optionally respects `robots.txt`.

2. `request_engine.py`
- Wraps HTTP requests and session handling.
- Implements safe request throttling/rate limiting.

3. `payloads.py`
- Holds maintainable, non-destructive payload sets for SQLi/XSS/SSRF/LFI and IDOR mutation strategies.

4. `detectors/*`
- One detector per vulnerability class:
  - SQL Injection (error and time-based)
  - Reflected XSS
  - CSRF token checks
  - SSRF parameter probing
  - Local File Inclusion (LFI) / arbitrary file read checks
  - IDOR heuristic testing
  - Secrets in JavaScript
  - Server-Side Template Injection (SSTI) via arithmetic evaluation
  - OS Command Injection (time-based differential + out-of-band)
  - XML External Entity (XXE) injection (in-band file read + out-of-band)
- New checks can be added as plugins without changing scanner core.

5. `registry.py`
- Detector plugin registration and loading.

6. `reporting.py`
- Console summary, JSON report generation, and HTML report generation in `Reports/`.

7. `api_discovery.py`
- Probes conventional locations for OpenAPI/Swagger specs, GraphQL endpoints, and SOAP/WSDL definitions.
- Validates each hit by parsing it (not just status codes), follows Swagger-UI/Redoc pages to their spec URL, and classifies GraphQL introspection exposure.
- Confirmed URLs are seeded so the crawler and every detector test them too.

8. `fingerprint.py`
- Passively identifies the technology stack (web server, language, framework, CMS, JS libraries, WAF/CDN) from headers, cookies, and body markers.
- Reports a technology inventory and flags components whose detected version matches a known-vulnerable range.
- Detected technologies are exposed on the scan context and tailor detector payloads (e.g. LFI adds php://filter source-disclosure wrappers when PHP is detected; command injection tries Windows payloads first on Windows stacks).

9. `main.py`
- CLI entrypoint that orchestrates discovery, detector execution, and reporting.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m scanner.main --url https://example.org --max-pages 30 --output report.json
```

Optional args:

- `--allow-external`: allow off-domain crawling (disabled by default)
- `--ignore-robots`: skip robots.txt handling
- `--delay`: delay between requests in seconds (default: `0.2`)
- `--timeout`: request timeout (default: `10`)
- `--cookie`: repeatable cookies (`name=value`) for authenticated context
- `--header`: repeatable headers (`Name: value`)
- `--seed-url`: repeatable explicit endpoint URL to test even if crawler misses it
- `--lfi-aggressive`: test all parameters for LFI (not just file/path-like names)
- `--lfi-max-payloads`: cap LFI payloads per parameter (`0` means all payloads)
- `--sqli-aggressive`: test guessed SQLi parameters even when no query string exists
- `--sqli-matrix-bypass`: also test matrix path variant `;.css;` for each discovered URL
- `--sqli-max-payloads`: cap SQLi payloads per parameter (`0` means all payloads)
- `--sqli-param`: repeatable explicit SQLi parameter name (example: `--sqli-param custOrdId`)
- `--sqli-time-threshold`: timing delta threshold in seconds for SQLi timing signal
- `--sqli-baseline-samples`: baseline timing sample count
- `--sqli-test-samples`: probe timing sample count
- `--sqli-probe-log-limit`: max SQLi probe artifacts kept in report coverage
- `--ssti-max-payloads`: cap SSTI expression templates per parameter (`0` means all)
- `--cmdi-max-payloads`: cap command-injection sleep templates per parameter (`0` means all)
- `--cmdi-time-threshold`: minimum sleep-vs-control timing delta in seconds to flag command injection
- `--cmdi-baseline-samples`: baseline timing sample count for command injection
- `--cmdi-test-samples`: probe timing sample count per command-injection payload
- `--xxe-max-payloads`: cap in-band XXE templates per endpoint (`0` means all)
- `--no-api-discovery`: disable well-known API definition discovery (enabled by default)
- `--api-discovery-max-paths`: cap well-known API paths probed per category (`0` means all)
- `--no-fingerprint`: disable passive technology fingerprinting (enabled by default)

## Exit Codes

- `0`: no high or critical findings
- `2`: one or more high/critical findings detected
- `3`: scanner runtime error

## Report Outputs

- JSON report is written to the `--output` path.
- HTML report is always written to `Reports/` with a timestamped filename.
- The HTML report title includes the target URL.

## Notes

- IDOR detection is heuristic and stronger when authenticated context is provided.
- Blind SSRF confirmation may require out-of-band infrastructure.
- LFI detection is heuristic and endpoint-agnostic (query and form parameters with file/path semantics). When PHP is fingerprinted it also tries php://filter wrappers and decodes base64 output to confirm source/file disclosure.
- SSTI detection is arithmetic and engine-agnostic (renders an injected product between random sentinels), yielding high-confidence, low-false-positive results.
- OS command injection uses a time-based differential (sleep vs. matching no-sleep payload) so uniformly slow endpoints do not false-positive; configure an OAST server to also confirm blind execution.
- XXE probes XML-accepting endpoints for in-band file disclosure and (with `--oast-server`) blind external-entity callbacks.
- API definition discovery validates OpenAPI/Swagger specs and GraphQL/WSDL endpoints by parsing them, so hits are confirmed rather than guessed; discovered URLs feed the crawler and all detectors.
- Technology fingerprinting is passive (header/cookie/body signatures); version-based CVE advisories are inferred and flagged at medium/low confidence — confirm the deployed version before relying on them.
- Use known vulnerable labs (e.g., local intentionally vulnerable apps) for validation.
