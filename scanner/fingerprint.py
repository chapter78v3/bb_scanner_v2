"""Passive technology fingerprinting.

Identifies the target's technology stack (web server, language, framework, CMS,
JS libraries, WAF/CDN) from response headers, cookies, and body markers, then:

* records a technology inventory finding (informational),
* flags components whose detected version matches a known-vulnerable range, and
* exposes the detected technologies on the scan context so detectors can tailor
  their payloads (e.g. prioritise PHP wrappers when PHP is present).

Detection is signature-driven and endpoint-agnostic. Version numbers are only
reported when a signature actually captures one, keeping the output high-signal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .models import Finding
from .request_engine import RequestEngine


@dataclass
class Technology:
    name: str
    category: str
    version: Optional[str] = None
    evidence: str = ""
    confidence: str = "medium"


@dataclass
class FingerprintResult:
    technologies: List[Technology] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def names(self) -> List[str]:
        return sorted({t.name for t in self.technologies})


# (header_name, compiled_regex_over_value, tech_name, category, version_group_index)
_HEADER_SIGNATURES: Tuple[Tuple[str, re.Pattern, str, str, int], ...] = (
    ("server", re.compile(r"nginx(?:/([\d.]+))?", re.I), "nginx", "web-server", 1),
    ("server", re.compile(r"apache(?:/([\d.]+))?", re.I), "Apache httpd", "web-server", 1),
    ("server", re.compile(r"microsoft-iis(?:/([\d.]+))?", re.I), "Microsoft IIS", "web-server", 1),
    ("server", re.compile(r"litespeed", re.I), "LiteSpeed", "web-server", 0),
    ("server", re.compile(r"openresty(?:/([\d.]+))?", re.I), "OpenResty", "web-server", 1),
    ("server", re.compile(r"gunicorn(?:/([\d.]+))?", re.I), "Gunicorn", "app-server", 1),
    ("server", re.compile(r"werkzeug(?:/([\d.]+))?", re.I), "Werkzeug (Flask)", "framework", 1),
    ("server", re.compile(r"kestrel", re.I), "Kestrel (ASP.NET Core)", "app-server", 0),
    ("server", re.compile(r"(?:apache-)?coyote", re.I), "Apache Tomcat", "app-server", 0),
    ("server", re.compile(r"jetty(?:\(([\d.]+)\))?", re.I), "Jetty", "app-server", 1),
    ("server", re.compile(r"caddy", re.I), "Caddy", "web-server", 0),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare", "cdn-waf", 0),
    ("x-powered-by", re.compile(r"php/?([\d.]+)?", re.I), "PHP", "language", 1),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET", "framework", 0),
    ("x-powered-by", re.compile(r"express", re.I), "Express (Node.js)", "framework", 0),
    ("x-powered-by", re.compile(r"next\.js", re.I), "Next.js", "framework", 0),
    ("x-powered-by", re.compile(r"servlet", re.I), "Java Servlet", "framework", 0),
    ("x-aspnet-version", re.compile(r"([\d.]+)"), "ASP.NET", "framework", 1),
    ("x-aspnetmvc-version", re.compile(r"([\d.]+)"), "ASP.NET MVC", "framework", 1),
    ("x-drupal-cache", re.compile(r".+"), "Drupal", "cms", 0),
    ("x-generator", re.compile(r"drupal\s*([\d.]+)?", re.I), "Drupal", "cms", 1),
    ("x-shopify-stage", re.compile(r".+", re.I), "Shopify", "cms", 0),
    ("x-sucuri-id", re.compile(r".+", re.I), "Sucuri WAF", "cdn-waf", 0),
)

# (cookie_name_regex, tech_name, category)
_COOKIE_SIGNATURES: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"^phpsessid$", re.I), "PHP", "language"),
    (re.compile(r"^laravel_session$", re.I), "Laravel", "framework"),
    (re.compile(r"^ci_session$", re.I), "CodeIgniter", "framework"),
    (re.compile(r"^jsessionid$", re.I), "Java", "language"),
    (re.compile(r"^asp\.net_sessionid$", re.I), "ASP.NET", "framework"),
    (re.compile(r"^\.aspxauth$", re.I), "ASP.NET", "framework"),
    (re.compile(r"^wordpress_", re.I), "WordPress", "cms"),
    (re.compile(r"^wp-settings", re.I), "WordPress", "cms"),
    (re.compile(r"^_session_id$", re.I), "Ruby on Rails", "framework"),
    (re.compile(r"^connect\.sid$", re.I), "Express (Node.js)", "framework"),
    (re.compile(r"^django", re.I), "Django", "framework"),
    (re.compile(r"^csrftoken$", re.I), "Django", "framework"),
)

# (compiled_regex_over_body, tech_name, category, version_group_index)
_BODY_SIGNATURES: Tuple[Tuple[re.Pattern, str, str, int], ...] = (
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']wordpress\s*([\d.]+)?', re.I), "WordPress", "cms", 1),
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']drupal\s*([\d.]+)?', re.I), "Drupal", "cms", 1),
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']joomla', re.I), "Joomla", "cms", 0),
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']ghost\s*([\d.]+)?', re.I), "Ghost", "cms", 1),
    (re.compile(r"/wp-(?:content|includes)/", re.I), "WordPress", "cms", 0),
    (re.compile(r"/sites/(?:all|default)/", re.I), "Drupal", "cms", 0),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify", "cms", 0),
    (re.compile(r"__NEXT_DATA__", ), "Next.js", "framework", 0),
    (re.compile(r"ng-version=[\"']([\d.]+)[\"']", re.I), "Angular", "framework", 1),
    (re.compile(r"data-reactroot|react(?:-dom)?\.production", re.I), "React", "framework", 0),
    (re.compile(r"__vue__|v-cloak|vue(?:\.runtime)?\.min\.js", re.I), "Vue.js", "framework", 0),
    (re.compile(r'name=["\']csrf-param["\'][^>]+content=["\']authenticity_token', re.I), "Ruby on Rails", "framework", 0),
    (re.compile(r"Laravel", ), "Laravel", "framework", 0),
    (re.compile(r"jQuery\s+v?([\d.]+)", re.I), "jQuery", "js-library", 1),
)

# Script-source / asset URL patterns (from <script src> and discovered JS files).
_SCRIPT_SIGNATURES: Tuple[Tuple[re.Pattern, str, str, int], ...] = (
    (re.compile(r"jquery[.-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.js", re.I), "jQuery", "js-library", 1),
    (re.compile(r"bootstrap[.-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.(?:js|css)", re.I), "Bootstrap", "js-library", 1),
    (re.compile(r"angular[.-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.js", re.I), "AngularJS", "js-library", 1),
    (re.compile(r"vue[@/.-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.js", re.I), "Vue.js", "js-library", 1),
    (re.compile(r"react[.-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.js", re.I), "React", "js-library", 1),
    (re.compile(r"lodash[.-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.js", re.I), "Lodash", "js-library", 1),
    (re.compile(r"/([\d]+\.[\d]+\.[\d]+)/angular", re.I), "AngularJS", "js-library", 1),
)

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)

# Known-vulnerable component advisories. Each: (tech, max_safe_version, applies_if,
# cve, description). ``applies_if`` optionally restricts by a major-version prefix
# so a Bootstrap 3 rule does not fire on Bootstrap 5. Versions are heuristic, so
# findings stay at 'medium' with an explicit "potentially vulnerable" framing.
_ADVISORIES: Tuple[Dict[str, str], ...] = (
    {"tech": "jQuery", "max_safe": "3.5.0", "prefix": "",
     "cve": "CVE-2020-11022 / CVE-2020-11023",
     "desc": "jQuery before 3.5.0 is affected by cross-site scripting via passing HTML from untrusted sources to DOM manipulation methods."},
    {"tech": "Bootstrap", "max_safe": "3.4.1", "prefix": "3.",
     "cve": "CVE-2019-8331",
     "desc": "Bootstrap 3.x before 3.4.1 is affected by XSS in the data-template/data-content tooltip and popover attributes."},
    {"tech": "Bootstrap", "max_safe": "4.3.1", "prefix": "4.",
     "cve": "CVE-2019-8331",
     "desc": "Bootstrap 4.x before 4.3.1 is affected by XSS in the tooltip/popover data attributes."},
    {"tech": "Lodash", "max_safe": "4.17.21", "prefix": "",
     "cve": "CVE-2021-23337 / CVE-2020-8203",
     "desc": "Lodash before 4.17.21 is affected by command injection via template and prototype pollution."},
)


class Fingerprinter:
    """Passive technology fingerprinting over the target root and crawl artifacts."""

    def __init__(self, engine: RequestEngine) -> None:
        self.engine = engine

    def fingerprint(self, target_url: str, crawl=None) -> FingerprintResult:
        result = FingerprintResult()
        found: Dict[Tuple[str, Optional[str]], Technology] = {}

        print("\n=== Technology fingerprint ===")

        headers, cookie_names, body, root_scripts = self._gather(target_url, crawl)

        for tech in self._from_headers(headers):
            self._merge(found, tech)
        for tech in self._from_cookies(cookie_names):
            self._merge(found, tech)
        for tech in self._from_body(body):
            self._merge(found, tech)

        script_urls = set(root_scripts)
        if crawl is not None:
            script_urls.update(crawl.js_files or [])
        for tech in self._from_scripts(script_urls):
            self._merge(found, tech)

        result.technologies = sorted(found.values(), key=lambda t: (t.category, t.name))

        if result.technologies:
            result.findings.append(self._inventory_finding(target_url, result.technologies))
        result.findings.extend(self._advisory_findings(target_url, result.technologies))

        if result.technologies:
            summary = ", ".join(
                f"{t.name}{(' ' + t.version) if t.version else ''}" for t in result.technologies
            )
            print(f"  Detected: {summary}")
        else:
            print("  No technologies fingerprinted from passive signals.")
        for finding in result.findings:
            if finding.severity != "info":
                print(f"    [!] {finding.severity.upper():8} {finding.vulnerability} -> {finding.url}")
        return result

    # -- Signal gathering ---------------------------------------------------

    def _gather(self, target_url: str, crawl):
        headers: Dict[str, str] = {}
        cookie_names: set = set()
        body = ""
        scripts: List[str] = []

        try:
            response = self.engine.get(target_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            for name in response.cookies.keys():
                cookie_names.add(name)
            body = response.text or ""
            scripts = [m.group(1) for m in _SCRIPT_SRC_RE.finditer(body)]
        except Exception:
            pass

        # Fold in headers/cookies captured across the crawl for broader coverage.
        if crawl is not None:
            for obs in crawl.observations or []:
                for key, value in (obs.headers or {}).items():
                    headers.setdefault(key.lower(), value)
                for raw in obs.set_cookie or []:
                    first = raw.split(";", 1)[0]
                    if "=" in first:
                        cookie_names.add(first.split("=", 1)[0].strip())
        return headers, cookie_names, body, scripts

    # -- Signature matching -------------------------------------------------

    def _from_headers(self, headers: Dict[str, str]) -> List[Technology]:
        techs: List[Technology] = []
        for header_name, regex, name, category, group in _HEADER_SIGNATURES:
            value = headers.get(header_name)
            if not value:
                continue
            match = regex.search(value)
            if not match:
                continue
            version = match.group(group) if group and match.lastindex and group <= match.lastindex else None
            techs.append(Technology(name, category, version, f"header {header_name}: {value}", "high"))
        return techs

    def _from_cookies(self, cookie_names) -> List[Technology]:
        techs: List[Technology] = []
        for name in cookie_names:
            for regex, tech_name, category in _COOKIE_SIGNATURES:
                if regex.search(name):
                    techs.append(Technology(tech_name, category, None, f"cookie {name}", "medium"))
        return techs

    def _from_body(self, body: str) -> List[Technology]:
        techs: List[Technology] = []
        if not body:
            return techs
        window = body[:200000]
        for regex, name, category, group in _BODY_SIGNATURES:
            match = regex.search(window)
            if not match:
                continue
            version = match.group(group) if group and match.lastindex and group <= match.lastindex else None
            techs.append(Technology(name, category, version, "body signature", "medium"))
        return techs

    def _from_scripts(self, script_urls) -> List[Technology]:
        techs: List[Technology] = []
        for url in script_urls:
            for regex, name, category, group in _SCRIPT_SIGNATURES:
                match = regex.search(url)
                if not match:
                    continue
                version = match.group(group) if group and match.lastindex and group <= match.lastindex else None
                techs.append(Technology(name, category, version, f"asset {urlparse(url).path or url}", "high"))
        return techs

    @staticmethod
    def _merge(found: Dict[Tuple[str, Optional[str]], Technology], tech: Technology) -> None:
        # Prefer a versioned detection over an unversioned one for the same tech.
        existing_versionless = (tech.name, None)
        if tech.version is not None and existing_versionless in found:
            del found[existing_versionless]
        key = (tech.name, tech.version)
        versioned_exists = any(k[0] == tech.name and k[1] is not None for k in found)
        if tech.version is None and versioned_exists:
            return
        if key not in found:
            found[key] = tech

    # -- Findings -----------------------------------------------------------

    def _inventory_finding(self, target_url: str, technologies: List[Technology]) -> Finding:
        inventory = "; ".join(
            f"{t.name}{(' ' + t.version) if t.version else ''} ({t.category})" for t in technologies
        )
        return Finding(
            vulnerability="Technology Fingerprint",
            severity="info",
            cwe="CWE-200",
            owasp="A05:2021 Security Misconfiguration",
            url=target_url,
            parameter=None,
            description=(
                "Passive fingerprinting identified the technology stack below. This inventory "
                "guides targeted testing and highlights components to check for known CVEs."
            ),
            evidence=inventory,
            detector="fingerprint",
            confidence="high",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )

    def _advisory_findings(self, target_url: str, technologies: List[Technology]) -> List[Finding]:
        findings: List[Finding] = []
        for tech in technologies:
            if tech.version is None:
                continue
            for adv in _ADVISORIES:
                if adv["tech"] != tech.name:
                    continue
                if adv["prefix"] and not tech.version.startswith(adv["prefix"]):
                    continue
                if _version_lt(tech.version, adv["max_safe"]):
                    findings.append(
                        Finding(
                            vulnerability=f"Potentially Vulnerable Component: {tech.name} {tech.version}",
                            severity="medium",
                            cwe="CWE-1035",
                            owasp="A06:2021 Vulnerable and Outdated Components",
                            url=target_url,
                            parameter=None,
                            description=(
                                f"{adv['desc']} Detected {tech.name} {tech.version}; the fix is "
                                f"{adv['max_safe']} or later. Version was inferred passively — confirm "
                                f"the deployed version before relying on this."
                            ),
                            evidence=f"{tech.name} {tech.version} < {adv['max_safe']}; {adv['cve']}; {tech.evidence}",
                            detector="fingerprint",
                            confidence="low",
                            references=[f"https://nvd.nist.gov/vuln/search/results?query={adv['cve'].split(' ')[0]}"],
                        )
                    )
                    break
        return findings


def _parse_version(version: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for chunk in re.split(r"[.\-_]", version):
        digits = re.match(r"\d+", chunk)
        if digits:
            parts.append(int(digits.group(0)))
        else:
            break
    return tuple(parts)


def _version_lt(version: str, other: str) -> bool:
    """Return True if ``version`` < ``other`` using numeric component comparison."""
    a = _parse_version(version)
    b = _parse_version(other)
    if not a:
        return False
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return a < b
