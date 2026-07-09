"""Detector package and default plugin registration."""

from .aem import AEMDispatcherDetector
from .cors import CORSMisconfigurationDetector
from .csrf import CSRFFDetector
from .cmdi import CommandInjectionDetector
from .dom_xss import DomXssDetector
from .idor import IDORDetector
from .lfi import LFIDetector
from .open_redirect import OpenRedirectDetector
from .passive import PassiveHeadersDetector
from .secrets_js import JavaScriptSecretsDetector
from .sqli import SQLiDetector
from .ssrf import SSRFDetector
from .ssti import SSTIDetector
from .takeover import SubdomainTakeoverDetector
from .xss import XSSDetector
from .xxe import XXEDetector

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
    CORSMisconfigurationDetector,
    OpenRedirectDetector,
    SSTIDetector,
    CommandInjectionDetector,
    XXEDetector,
    AEMDispatcherDetector,
]
