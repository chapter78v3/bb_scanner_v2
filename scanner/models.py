from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FormField:
    """Represents an input-like field extracted from an HTML form."""

    name: str
    field_type: str = "text"
    value: str = ""


@dataclass
class FormDescriptor:
    """Represents a discovered HTML form and its submission metadata."""

    page_url: str
    action_url: str
    method: str
    fields: List[FormField] = field(default_factory=list)


@dataclass
class PageObservation:
    """Passive record of a fetched page's response metadata (no extra requests)."""

    url: str
    status_code: int
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    set_cookie: List[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    """Discovery output consumed by detector plugins."""

    urls: List[str] = field(default_factory=list)
    forms: List[FormDescriptor] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    observations: List[PageObservation] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class Finding:
    """A normalized vulnerability finding record."""

    vulnerability: str
    severity: str
    cwe: str
    owasp: str
    url: str
    parameter: Optional[str]
    description: str
    evidence: str
    detector: str
    confidence: str = "medium"
    references: List[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Shared context passed to detectors."""

    target_url: str
    crawl: CrawlResult
    allow_external: bool
    respect_robots: bool
    authenticated: bool
    lfi_aggressive: bool = False
    lfi_max_payloads: int = 0
    sqli_aggressive: bool = False
    sqli_matrix_bypass: bool = False
    sqli_max_payloads: int = 0
    sqli_custom_params: List[str] = field(default_factory=list)
    sqli_time_threshold: float = 2.2
    sqli_baseline_samples: int = 3
    sqli_test_samples: int = 3
    sqli_probe_log_limit: int = 200
    # Injection detectors (SSTI / command injection / XXE).
    ssti_max_payloads: int = 0
    cmdi_max_payloads: int = 0
    cmdi_time_threshold: float = 4.0
    cmdi_baseline_samples: int = 2
    cmdi_test_samples: int = 2
    xxe_max_payloads: int = 0
    seed_urls: List[str] = field(default_factory=list)
    oast: Any = None
    secondary_engine: Any = None
    renderer: Any = None
    technologies: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
