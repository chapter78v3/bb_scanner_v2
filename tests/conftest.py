"""Shared pytest setup.

The integration tests spin up throwaway HTTP servers on 127.0.0.1. In corporate
environments an ``HTTP_PROXY``/``HTTPS_PROXY`` is often exported globally, which
makes ``requests`` route even loopback traffic through the proxy and receive a
block page instead of the test server's response. Ensure loopback always
bypasses any configured proxy so the suite is deterministic regardless of the
host's proxy configuration.
"""
import os

_LOOPBACK = "127.0.0.1,localhost,::1"

_existing = os.environ.get("NO_PROXY", "")
_entries = [e.strip() for e in _existing.split(",") if e.strip()]
for _host in _LOOPBACK.split(","):
    if _host not in _entries:
        _entries.append(_host)

os.environ["NO_PROXY"] = ",".join(_entries)
os.environ["no_proxy"] = os.environ["NO_PROXY"]
