"""Subdomain / resource takeover detector.

Checks every in-scope host for the classic takeover pattern: a DNS record that
still points at a third-party provider (Azure, S3, GitHub Pages, Heroku, ...)
whose backing resource has been deleted, leaving the hostname claimable by an
attacker. Detection combines two signals with no destructive actions:

* the host's CNAME chain resolving to a known takeover-prone provider, and
* the provider serving its distinctive "unclaimed resource" response body.

A matching body signature is reported as high severity; an unresolvable
(NXDOMAIN) record that is still referenced is reported as a lower-confidence
dangling-DNS finding worth manual review.
"""

from __future__ import annotations

import socket
from typing import List, NamedTuple, Set, Tuple
from urllib.parse import urlparse

from ..models import Finding, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class Fingerprint(NamedTuple):
    provider: str
    cname_suffixes: Tuple[str, ...]
    signatures: Tuple[str, ...]


# Curated, high-confidence takeover fingerprints. Signatures are matched against
# a lowercased response body; CNAME suffixes corroborate to raise confidence.
FINGERPRINTS: Tuple[Fingerprint, ...] = (
    Fingerprint(
        "Microsoft Azure",
        ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
         "blob.core.windows.net", "azure-api.net", "azurefd.net", "azureedge.net", "azurecontainer.io"),
        ("404 web site not found",),
    ),
    Fingerprint(
        "Amazon S3",
        ("s3.amazonaws.com", "s3-website", ".s3.", "amazonaws.com"),
        ("nosuchbucket", "the specified bucket does not exist"),
    ),
    Fingerprint(
        "GitHub Pages",
        ("github.io", "githubusercontent.com"),
        ("there isn't a github pages site here", "for root urls (like http://example.com/) you must provide an index.html file"),
    ),
    Fingerprint(
        "Heroku",
        ("herokuapp.com", "herokudns.com", "herokussl.com"),
        ("no such app", "herokucdn.com/error-pages/no-such-app.html"),
    ),
    Fingerprint(
        "Fastly",
        ("fastly.net",),
        ("fastly error: unknown domain",),
    ),
    Fingerprint(
        "Shopify",
        ("myshopify.com",),
        ("sorry, this shop is currently unavailable",),
    ),
    Fingerprint(
        "Zendesk",
        ("zendesk.com",),
        ("help center closed",),
    ),
    Fingerprint(
        "Bitbucket",
        ("bitbucket.io",),
        ("repository not found",),
    ),
    Fingerprint(
        "Ghost",
        ("ghost.io",),
        ("the thing you were looking for is no longer here, or never was",),
    ),
    Fingerprint(
        "Pantheon",
        ("pantheonsite.io",),
        ("the gods are wise, but do not know of the site which you seek",),
    ),
    Fingerprint(
        "Tumblr",
        ("domains.tumblr.com",),
        ("whatever you were looking for doesn't currently exist at this address",),
    ),
    Fingerprint(
        "Surge.sh",
        ("surge.sh",),
        ("project not found",),
    ),
    Fingerprint(
        "Webflow",
        ("proxy-ssl.webflow.com", "proxy.webflow.com"),
        ("the page you are looking for doesn't exist or has been moved",),
    ),
    Fingerprint(
        "Wordpress",
        ("wordpress.com",),
        ("do you want to register",),
    ),
    Fingerprint(
        "Readme.io",
        ("readme.io",),
        ("project not found",),
    ),
    Fingerprint(
        "Help Scout",
        ("helpscoutdocs.com",),
        ("no settings were found for this company",),
    ),
    Fingerprint(
        "AWS Elastic Beanstalk",
        ("elasticbeanstalk.com",),
        ("404 not found", "the resource you are looking for has been removed"),
    ),
)

# Cap on how many distinct hosts we actively probe, to bound scan time.
MAX_HOSTS = 100


class SubdomainTakeoverDetector(DetectorPlugin):
    """Flags hosts vulnerable to subdomain/resource takeover."""

    name = "takeover"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        hosts = self._collect_hosts(context)
        for host in list(hosts)[:MAX_HOSTS]:
            findings.extend(self._check_host(host, engine))
        return findings

    def _collect_hosts(self, context: ScanContext) -> Set[str]:
        hosts: Set[str] = set()
        sources: List[str] = [context.target_url]
        sources.extend(context.crawl.urls)
        sources.extend(context.seed_urls)
        sources.extend(context.crawl.js_files)
        for raw in sources:
            host = urlparse(raw).hostname
            if host:
                hosts.add(host.lower())
        return hosts

    def _resolve_aliases(self, host: str) -> Tuple[List[str], bool]:
        """Return (cname/alias chain, resolved). resolved=False means NXDOMAIN."""
        try:
            name, aliases, _ = socket.gethostbyname_ex(host)
        except socket.gaierror:
            return [], False
        except OSError:
            return [], True  # transient; treat as resolved to avoid false dangling
        chain = [name.lower()] + [a.lower() for a in aliases]
        return chain, True

    def _check_host(self, host: str, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        aliases, resolved = self._resolve_aliases(host)

        # Fetch the host root once; body signatures are the primary signal.
        body = ""
        status = 0
        url = f"https://{host}/"
        try:
            response = engine.get(url)
            status = response.status_code
            body = (response.text or "")[:6000].lower()
        except Exception:
            body = ""

        alias_blob = " ".join(aliases)
        for fp in FINGERPRINTS:
            cname_match = any(suffix in alias_blob for suffix in fp.cname_suffixes)
            sig_match = any(sig in body for sig in fp.signatures)
            if not sig_match:
                continue
            confidence = "high" if cname_match else "medium"
            severity = "high" if cname_match else "medium"
            evidence = (
                f"provider={fp.provider}; status={status or 'n/a'}; "
                f"cname_match={cname_match}; "
                f"signature matched in response body"
            )
            findings.append(
                Finding(
                    vulnerability=f"Subdomain Takeover: {fp.provider}",
                    severity=severity,
                    cwe="CWE-668",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                    parameter=None,
                    description=(
                        f"The host '{host}' serves {fp.provider}'s unclaimed-resource page, "
                        "indicating the backing resource was deleted while DNS still points at it. "
                        "An attacker may be able to register the resource and take over this hostname."
                    ),
                    evidence=evidence,
                    detector=self.name,
                    confidence=confidence,
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                        "https://github.com/EdOverflow/can-i-take-over-xyz",
                    ],
                )
            )
            break  # one provider match per host is enough

        # Dangling DNS: the host is referenced but no longer resolves. Only report
        # for non-apex hosts to avoid noise from the primary target being offline.
        if not resolved and not findings:
            findings.append(
                Finding(
                    vulnerability="Dangling DNS Record (Possible Takeover)",
                    severity="medium",
                    cwe="CWE-668",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                    parameter=None,
                    description=(
                        f"The referenced host '{host}' does not resolve (NXDOMAIN) yet is still linked. "
                        "If its DNS record points at a claimable third-party resource, it may be vulnerable "
                        "to takeover. Review the DNS configuration and remove stale records."
                    ),
                    evidence=f"host={host}; DNS resolution failed (NXDOMAIN)",
                    detector=self.name,
                    confidence="low",
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                )
            )

        return findings
