"""Detector package and default plugin registration."""

from .csrf import CSRFFDetector
from .dom_xss import DomXssDetector
from .idor import IDORDetector
from .lfi import LFIDetector
from .passive import PassiveHeadersDetector
from .secrets_js import JavaScriptSecretsDetector
from .sqli import SQLiDetector
from .ssrf import SSRFDetector
from .takeover import SubdomainTakeoverDetector
from .xss import XSSDetector

DEFAULT_DETECTORS = [
    SQLiDetector,
    XSSDetector,
    CSRFFDetector,
    SSRFDetector,
    LFIDetector,
    IDORDetector,
    JavaScriptSecretsDetector,
    PassiveHeadersDetector,
    DomXssDetector,
    SubdomainTakeoverDetector,
]
