"""Tests for well-known API definition discovery.

A throwaway server emulates OpenAPI/Swagger and GraphQL endpoints at their
conventional locations so we can lock in confirmation (parsing, not just status
codes), Swagger-UI spec following, GraphQL introspection classification, and
false-positive suppression when nothing API-like is exposed.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from scanner.api_discovery import APISpecDiscovery
from scanner.request_engine import RequestEngine

_OPENAPI_DOC = {
    "openapi": "3.0.1",
    "info": {"title": "Demo", "version": "1.0"},
    "paths": {"/users": {"get": {}}, "/users/{id}": {"get": {}}},
}


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _make_server(routes_get=None, graphql_mode=None, ui=False):
    routes_get = routes_get or {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body.encode() if isinstance(body, str) else body)

        def do_GET(self):
            path = urlparse(self.path).path.lstrip("/")
            if ui and path == "swagger-ui.html":
                self._send(200, '<html><script>SwaggerUIBundle({url: "/v3/api-docs"})</script></html>', "text/html")
                return
            if path in routes_get:
                ctype, body = routes_get[path]
                self._send(200, body, ctype)
                return
            self._send(404, "not found", "text/plain")

        def do_POST(self):
            path = urlparse(self.path).path.lstrip("/")
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode(errors="ignore")
            if graphql_mode and path == "graphql":
                if "__schema" in body:
                    if graphql_mode == "introspect":
                        self._send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}))
                    else:  # disabled: schema query errors, minimal query works
                        self._send(200, json.dumps({"errors": [{"message": "introspection disabled"}]}))
                    return
                self._send(200, json.dumps({"data": {"__typename": "Query"}}))
                return
            self._send(404, "not found", "text/plain")

    return _serve(H)


def test_openapi_spec_confirmed_and_flagged():
    srv, base = _make_server(routes_get={"openapi.json": ("application/json", json.dumps(_OPENAPI_DOC))})
    try:
        result = APISpecDiscovery(RequestEngine(delay_seconds=0.0)).discover(base)
        assert len(result.specs) == 1
        assert result.specs[0].url == f"{base}/openapi.json"
        assert any("OpenAPI/Swagger Specification" in f.vulnerability for f in result.findings)
        assert f"{base}/openapi.json" in result.discovered_urls
    finally:
        srv.shutdown()


def test_swagger_ui_followed_to_spec():
    srv, base = _make_server(
        routes_get={"v3/api-docs": ("application/json", json.dumps(_OPENAPI_DOC))},
        ui=True,
    )
    try:
        result = APISpecDiscovery(RequestEngine(delay_seconds=0.0)).discover(base)
        assert any(s.url == f"{base}/v3/api-docs" for s in result.specs)
    finally:
        srv.shutdown()


def test_graphql_introspection_enabled_is_medium():
    srv, base = _make_server(graphql_mode="introspect")
    try:
        result = APISpecDiscovery(RequestEngine(delay_seconds=0.0)).discover(base)
        intro = [f for f in result.findings if "Introspection Enabled" in f.vulnerability]
        assert intro and intro[0].severity == "medium"
        assert f"{base}/graphql" in result.graphql_endpoints
    finally:
        srv.shutdown()


def test_graphql_introspection_disabled_is_low():
    srv, base = _make_server(graphql_mode="disabled")
    try:
        result = APISpecDiscovery(RequestEngine(delay_seconds=0.0)).discover(base)
        assert not [f for f in result.findings if "Introspection Enabled" in f.vulnerability]
        exposed = [f for f in result.findings if f.vulnerability == "Exposed GraphQL Endpoint"]
        assert exposed and exposed[0].severity == "low"
    finally:
        srv.shutdown()


def test_no_api_surface_no_findings():
    srv, base = _make_server()
    try:
        result = APISpecDiscovery(RequestEngine(delay_seconds=0.0)).discover(base)
        assert not result.specs
        assert not result.graphql_endpoints
        assert not result.findings
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
