"""Tests for passive technology fingerprinting."""
import pytest

from scanner.fingerprint import Fingerprinter, _version_lt


class _FakeResponse:
    def __init__(self, headers=None, cookies=None, text=""):
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.text = text


class _FakeEngine:
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response


def _fp(headers=None, cookies=None, text=""):
    engine = _FakeEngine(_FakeResponse(headers, cookies, text))
    return Fingerprinter(engine).fingerprint("http://target.test/")


def _tech_map(result):
    return {t.name: t for t in result.technologies}


# --- version comparison ------------------------------------------------------

@pytest.mark.parametrize("lower,higher,expected", [
    ("3.4.1", "3.5.0", True),
    ("3.5.1", "3.5.0", False),
    ("4.17.20", "4.17.21", True),
    ("3.5.0", "3.5.0", False),
    ("2", "3.0.0", True),
])
def test_version_lt(lower, higher, expected):
    assert _version_lt(lower, higher) is expected


# --- header signatures -------------------------------------------------------

def test_header_fingerprint_server_and_language():
    result = _fp(headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"})
    techs = _tech_map(result)
    assert techs["nginx"].version == "1.18.0"
    assert techs["PHP"].version == "7.4.3"


def test_cookie_fingerprint_php():
    result = _fp(cookies={"PHPSESSID": "abc"})
    assert "PHP" in _tech_map(result)


def test_versioned_detection_wins_over_versionless():
    # PHP appears versioned in the header and versionless via the cookie: the
    # merged inventory should keep a single, versioned PHP entry.
    result = _fp(headers={"X-Powered-By": "PHP/8.1.0"}, cookies={"PHPSESSID": "x"})
    php_entries = [t for t in result.technologies if t.name == "PHP"]
    assert len(php_entries) == 1 and php_entries[0].version == "8.1.0"


# --- body signatures ---------------------------------------------------------

def test_body_meta_generator_wordpress():
    body = '<meta name="generator" content="WordPress 6.4.2" />'
    result = _fp(text=body)
    techs = _tech_map(result)
    assert "WordPress" in techs and techs["WordPress"].version == "6.4.2"


# --- script assets + advisories ---------------------------------------------

def test_script_version_flags_outdated_component():
    body = '<script src="/assets/jquery-3.4.1.min.js"></script>'
    result = _fp(text=body)
    techs = _tech_map(result)
    assert techs["jQuery"].version == "3.4.1"
    advisories = [f for f in result.findings if "Potentially Vulnerable Component" in f.vulnerability]
    assert advisories and "jQuery" in advisories[0].vulnerability


def test_current_library_version_not_flagged():
    body = '<script src="/assets/jquery-3.7.1.min.js"></script>'
    result = _fp(text=body)
    assert not [f for f in result.findings if "Potentially Vulnerable Component" in f.vulnerability]


def test_inventory_finding_emitted_when_tech_found():
    result = _fp(headers={"Server": "Apache/2.4.41"})
    inv = [f for f in result.findings if f.vulnerability == "Technology Fingerprint"]
    assert inv and inv[0].severity == "info"


def test_no_signals_no_findings():
    result = _fp()
    assert not result.technologies
    assert not result.findings


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
