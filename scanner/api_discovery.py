"""Well-known API definition discovery.

Probes a curated list of conventional locations where OpenAPI/Swagger specs,
GraphQL endpoints, and SOAP/WSDL definitions are exposed, then *validates* each
hit by parsing it (not just by status code) so the result is a confirmed,
low-false-positive signal. Discovered URLs are returned so the crawler and every
detector process them too, and parsed OpenAPI documents are handed back for the
downstream importer to expand into concrete operations.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .models import Finding
from .request_engine import RequestEngine

# Conventional OpenAPI/Swagger specification and UI locations, relative to the
# target root. Kept ordered from most to least common.
OPENAPI_PATHS: Tuple[str, ...] = (
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger/v1/swagger.json",
    "swagger/v2/swagger.json",
    "v2/api-docs",
    "v3/api-docs",
    "api-docs",
    "api/api-docs",
    "api/swagger.json",
    "api/openapi.json",
    "api/v1/openapi.json",
    "api/v2/openapi.json",
    "api/v3/openapi.json",
    "v1/openapi.json",
    "v2/openapi.json",
    "v3/openapi.json",
    ".well-known/openapi.json",
    "swagger-resources",
    "swagger-ui.html",
    "swagger/index.html",
    "swagger/",
    "api/docs",
    "api/documentation",
    "redoc",
)

# Conventional GraphQL endpoints. Probed with a minimal query + an introspection
# query so the detector can distinguish "endpoint exists" from the more serious
# "schema introspection is enabled".
GRAPHQL_PATHS: Tuple[str, ...] = (
    "graphql",
    "api/graphql",
    "v1/graphql",
    "graphql/console",
    "graphiql",
    "playground",
    "query",
    "gql",
)

# SOAP/WSDL service-definition probes (query-string suffix on the root/service).
WSDL_PATHS: Tuple[str, ...] = (
    "?wsdl",
    "service?wsdl",
    "services?wsdl",
)

_NOT_FOUND_STATUSES = {404, 410}
_ACCESS_DENIED_STATUSES = {401, 403, 407}

# Extract the spec URL a Swagger-UI / Redoc HTML page points at.
_SPEC_URL_PATTERNS = (
    re.compile(r"""url\s*:\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""urls\s*:\s*\[\s*\{\s*url\s*:\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""spec-?url\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""data-url\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
)

_INTROSPECTION_QUERY = '{"query":"query{__schema{queryType{name}}}"}'
_MINIMAL_QUERY = '{"query":"{__typename}"}'


@dataclass
class OpenAPISpec:
    """A confirmed, parsed OpenAPI/Swagger document."""

    url: str
    version: str
    document: Dict[str, object]


@dataclass
class APIDiscoveryResult:
    discovered_urls: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    specs: List[OpenAPISpec] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class APISpecDiscovery:
    """Discovers and validates well-known API definition endpoints."""

    def __init__(self, engine: RequestEngine, concurrency: int = 1, max_paths: int = 0) -> None:
        self.engine = engine
        self.concurrency = max(1, concurrency)
        self.max_paths = max(0, max_paths)

    # -- Public API ---------------------------------------------------------

    def discover(self, target_url: str) -> APIDiscoveryResult:
        result = APIDiscoveryResult()
        base = target_url if target_url.endswith("/") else target_url + "/"

        print("\n=== API definition discovery ===")

        openapi_paths = OPENAPI_PATHS
        if self.max_paths:
            openapi_paths = OPENAPI_PATHS[: self.max_paths]

        openapi_urls = [urljoin(base, path) for path in openapi_paths]
        probed = self._probe_many(openapi_urls)
        for url, payload in zip(openapi_urls, probed):
            if payload is None:
                continue
            status, ctype, body = payload
            self._handle_openapi_candidate(url, status, ctype, body, base, result)

        self._discover_graphql(base, result)
        self._discover_wsdl(base, result)

        # Deduplicate discovered URLs, preserving order.
        seen: set = set()
        deduped: List[str] = []
        for url in result.discovered_urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        result.discovered_urls = deduped

        spec_count = len(result.specs)
        print(
            f"  Confirmed {spec_count} OpenAPI/Swagger spec(s), "
            f"{len(result.graphql_endpoints)} GraphQL endpoint(s); "
            f"{len(result.findings)} finding(s)."
        )
        for finding in result.findings:
            print(f"    [!] {finding.severity.upper():8} {finding.vulnerability} -> {finding.url}")
        return result

    # -- OpenAPI / Swagger --------------------------------------------------

    def _handle_openapi_candidate(self, url, status, ctype, body, base, result: APIDiscoveryResult) -> None:
        if status in _NOT_FOUND_STATUSES or status in _ACCESS_DENIED_STATUSES:
            return

        spec = self._parse_openapi(url, body)
        if spec is None and self._looks_like_api_ui(body):
            # Swagger UI / Redoc page: follow the spec URL it references.
            spec_url = self._extract_spec_url(url, body)
            if spec_url:
                fetched = self._fetch(spec_url)
                if fetched is not None:
                    spec = self._parse_openapi(spec_url, fetched[2])
                    url = spec_url

        if spec is None:
            return

        path_count = len(spec.document.get("paths", {}) or {})
        result.specs.append(spec)
        result.discovered_urls.append(spec.url)
        result.findings.append(
            Finding(
                vulnerability="Exposed OpenAPI/Swagger Specification",
                severity="low",
                cwe="CWE-200",
                owasp="A09:2021 Security Logging and Monitoring Failures",
                url=spec.url,
                parameter=None,
                description=(
                    "A machine-readable API specification is publicly readable. It maps the "
                    "application's full attack surface (paths, parameters, and schemas) and is a "
                    "high-value input for targeted testing."
                ),
                evidence=f"format={spec.version}; operations={path_count}",
                detector="api_discovery",
                confidence="high",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
            )
        )

    def _parse_openapi(self, url: str, body: str) -> Optional[OpenAPISpec]:
        if not body:
            return None
        # JSON first.
        doc = None
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            doc = None
        if isinstance(doc, dict):
            version = self._openapi_version(doc)
            if version:
                return OpenAPISpec(url=url, version=version, document=doc)
            return None
        # YAML fallback (optional dependency).
        return self._parse_openapi_yaml(url, body)

    @staticmethod
    def _openapi_version(doc: Dict[str, object]) -> Optional[str]:
        if "openapi" in doc and isinstance(doc.get("openapi"), str):
            return f"openapi {doc['openapi']}"
        if "swagger" in doc and isinstance(doc.get("swagger"), str):
            return f"swagger {doc['swagger']}"
        # Some specs omit the version key but still carry a paths object.
        if isinstance(doc.get("paths"), dict) and doc.get("paths"):
            return "openapi (unversioned)"
        return None

    def _parse_openapi_yaml(self, url: str, body: str) -> Optional[OpenAPISpec]:
        try:
            import yaml  # type: ignore
        except Exception:
            # No YAML parser available: fall back to a conservative text check so
            # discovery still works, but do not attempt to expand operations.
            head = body[:2000].lower()
            if ("openapi:" in head or "swagger:" in head) and "paths:" in body.lower():
                return OpenAPISpec(url=url, version="openapi (yaml, unparsed)", document={})
            return None
        try:
            doc = yaml.safe_load(body)
        except Exception:
            return None
        if isinstance(doc, dict):
            version = self._openapi_version(doc)
            if version:
                return OpenAPISpec(url=url, version=f"{version} (yaml)", document=doc)
        return None

    @staticmethod
    def _looks_like_api_ui(body: str) -> bool:
        low = body[:8000].lower()
        return any(marker in low for marker in ("swagger-ui", "swaggerui", "redoc", "swagger ui"))

    @staticmethod
    def _extract_spec_url(page_url: str, body: str) -> Optional[str]:
        for pattern in _SPEC_URL_PATTERNS:
            match = pattern.search(body)
            if match:
                candidate = match.group(1).strip()
                # Ignore obvious non-spec assets referenced by the UI bundle.
                if candidate and not candidate.endswith((".css", ".png", ".ico", ".js")):
                    return urljoin(page_url, candidate)
        return None

    # -- GraphQL ------------------------------------------------------------

    def _discover_graphql(self, base: str, result: APIDiscoveryResult) -> None:
        paths = GRAPHQL_PATHS
        if self.max_paths:
            paths = GRAPHQL_PATHS[: self.max_paths]
        for path in paths:
            url = urljoin(base, path)
            introspection = self._graphql_introspects(url)
            if introspection is None:
                continue  # not a GraphQL endpoint
            result.graphql_endpoints.append(url)
            result.discovered_urls.append(url)
            if introspection:
                result.findings.append(
                    Finding(
                        vulnerability="GraphQL Introspection Enabled",
                        severity="medium",
                        cwe="CWE-200",
                        owasp="A05:2021 Security Misconfiguration",
                        url=url,
                        parameter=None,
                        description=(
                            "The GraphQL endpoint answers introspection queries, exposing the full "
                            "schema (types, queries, mutations). Introspection should be disabled in "
                            "production to limit attack-surface disclosure."
                        ),
                        evidence="query{__schema{queryType{name}}} returned a schema",
                        detector="api_discovery",
                        confidence="high",
                        references=["https://portswigger.net/web-security/graphql"],
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        vulnerability="Exposed GraphQL Endpoint",
                        severity="low",
                        cwe="CWE-200",
                        owasp="A05:2021 Security Misconfiguration",
                        url=url,
                        parameter=None,
                        description=(
                            "A GraphQL endpoint is reachable. Introspection appears disabled; verify "
                            "field-level authorization and rate limiting are enforced."
                        ),
                        evidence="responded to a GraphQL query",
                        detector="api_discovery",
                        confidence="medium",
                        references=["https://portswigger.net/web-security/graphql"],
                    )
                )

    def _graphql_introspects(self, url: str) -> Optional[bool]:
        """Return True if introspection is enabled, False if the endpoint exists
        but introspection is off, or None if this is not a GraphQL endpoint."""
        headers = {"Content-Type": "application/json"}
        try:
            resp = self.engine.post(url, data=_INTROSPECTION_QUERY, headers=headers)
        except Exception:
            return None
        if resp.status_code in _NOT_FOUND_STATUSES:
            return None
        parsed = self._json_or_none(resp.text)
        if isinstance(parsed, dict):
            data = parsed.get("data")
            if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
                return True
            if "errors" in parsed or "data" in parsed:
                # Valid GraphQL response shape, but no schema returned.
                return False
        # Fall back to the minimal query to confirm a GraphQL processor.
        try:
            resp2 = self.engine.post(url, data=_MINIMAL_QUERY, headers=headers)
        except Exception:
            return None
        parsed2 = self._json_or_none(resp2.text)
        if isinstance(parsed2, dict) and ("data" in parsed2 or "errors" in parsed2):
            return False
        return None

    # -- WSDL / SOAP --------------------------------------------------------

    def _discover_wsdl(self, base: str, result: APIDiscoveryResult) -> None:
        for path in WSDL_PATHS:
            url = urljoin(base, path)
            fetched = self._fetch(url)
            if fetched is None:
                continue
            status, ctype, body = fetched
            if status in _NOT_FOUND_STATUSES or status in _ACCESS_DENIED_STATUSES:
                continue
            low = (body or "")[:4000].lower()
            if "wsdl:definitions" in low or "<definitions" in low or "http://schemas.xmlsoap.org/wsdl" in low:
                result.discovered_urls.append(url)
                result.findings.append(
                    Finding(
                        vulnerability="Exposed SOAP/WSDL Service Definition",
                        severity="low",
                        cwe="CWE-200",
                        owasp="A09:2021 Security Logging and Monitoring Failures",
                        url=url,
                        parameter=None,
                        description=(
                            "A WSDL service definition is publicly readable and enumerates SOAP "
                            "operations, bindings, and message schemas — a full map of the service."
                        ),
                        evidence="response contained a WSDL <definitions> document",
                        detector="api_discovery",
                        confidence="high",
                        references=["https://owasp.org/www-community/vulnerabilities/WSDL_disclosure"],
                    )
                )

    # -- HTTP helpers -------------------------------------------------------

    def _probe_many(self, urls: List[str]) -> List[Optional[Tuple[int, str, str]]]:
        if self.concurrency > 1:
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                return list(executor.map(self._fetch, urls))
        return [self._fetch(url) for url in urls]

    def _fetch(self, url: str) -> Optional[Tuple[int, str, str]]:
        try:
            response = self.engine.get(url)
        except Exception:
            return None
        ctype = response.headers.get("Content-Type", "")
        try:
            body = response.text or ""
        except Exception:
            body = ""
        return response.status_code, ctype, body

    @staticmethod
    def _json_or_none(text: str):
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return None
