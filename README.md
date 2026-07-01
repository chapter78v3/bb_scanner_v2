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
- New checks can be added as plugins without changing scanner core.

5. `registry.py`
- Detector plugin registration and loading.

6. `reporting.py`
- Console summary, JSON report generation, and HTML report generation in `Reports/`.

7. `main.py`
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
- LFI detection is heuristic and endpoint-agnostic (query and form parameters with file/path semantics).
- Use known vulnerable labs (e.g., local intentionally vulnerable apps) for validation.
