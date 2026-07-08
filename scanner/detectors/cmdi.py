from __future__ import annotations

import statistics
import time
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, FormDescriptor, ScanContext
from ..payloads import CMDI_OAST_TEMPLATES, CMDI_SLEEP_TEMPLATES
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

_SLEEP_SECONDS = 5


class CommandInjectionDetector(DetectorPlugin):
    """Detects OS command injection via time-based differential and OAST probes.

    Primary signal is a *differential* blind delay: for each injection point the
    detector times a sleeping payload against an identical non-sleeping one over
    a median+MAD baseline (the same statistical rigor the SQLi timing checks
    use), so a uniformly slow endpoint cannot produce a false positive. When an
    out-of-band collaborator is configured, it also dispatches DNS/HTTP callback
    payloads that confirm blind command execution even with no reflected output.
    """

    name = "cmdi"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        for url in context.crawl.urls:
            findings.extend(self._test_url(url, engine, context))
        for form in context.crawl.forms:
            findings.extend(self._test_form(form, engine, context))
        return findings

    # -- Injection points ---------------------------------------------------

    def _test_url(self, url: str, engine: RequestEngine, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return findings

        base_get = lambda mutated: self._safe_get(engine, urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))))
        baseline_stats = self._timed_samples(lambda: base_get(params), context.cmdi_baseline_samples)
        if baseline_stats is None:
            return findings

        for param in params:
            def _send(value, p=param):
                mutated = dict(params)
                mutated[p] = value
                return base_get(mutated)

            finding = self._probe_point(param, context, baseline_stats, _send, url, param)
            if finding is not None:
                findings.append(finding)
            findings.extend(self._oast_probe(param, context, _send, url, param))
        return findings

    def _test_form(self, form: FormDescriptor, engine: RequestEngine, context: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        if not form.fields:
            return findings

        method = (form.method or "GET").upper()
        base = {field.name: (field.value or "scan") for field in form.fields}
        submit = lambda data: self._safe_submit(engine, form.action_url, method, data)
        baseline_stats = self._timed_samples(lambda: submit(base), context.cmdi_baseline_samples)
        if baseline_stats is None:
            return findings

        for field in form.fields:
            def _send(value, name=field.name):
                data = dict(base)
                data[name] = value
                return submit(data)

            finding = self._probe_point(field.name, context, baseline_stats, _send, form.action_url, field.name)
            if finding is not None:
                findings.append(finding)
            findings.extend(self._oast_probe(field.name, context, _send, form.action_url, field.name))
        return findings

    # -- Detection logic ----------------------------------------------------

    def _probe_point(self, param, context, baseline_stats, send, report_url, report_param) -> Optional[Finding]:
        baseline_median, baseline_mad = baseline_stats
        threshold = max(context.cmdi_time_threshold, baseline_mad * 5)
        for template in self._sleep_templates(context):
            sleep_payload = template.format(sec=_SLEEP_SECONDS, win=_SLEEP_SECONDS + 1)
            zero_payload = template.format(sec=0, win=1)

            sleep_stats = self._timed_samples(lambda: send(sleep_payload), context.cmdi_test_samples)
            if sleep_stats is None:
                continue
            sleep_median, _ = sleep_stats
            # Cheap pre-filter: only pay for the control run if the sleeping
            # payload actually looks slow relative to baseline.
            if sleep_median - baseline_median <= threshold:
                continue
            zero_stats = self._timed_samples(lambda: send(zero_payload), context.cmdi_test_samples)
            if zero_stats is None:
                continue
            zero_median, _ = zero_stats
            if sleep_median - zero_median > threshold:
                return Finding(
                    vulnerability="OS Command Injection (Time-based)",
                    severity="critical",
                    cwe="CWE-78",
                    owasp="A03:2021 Injection",
                    url=report_url,
                    parameter=report_param,
                    description=(
                        "A shell time-delay payload caused a response delay that a matching "
                        "non-sleeping payload did not, indicating the parameter is passed to an "
                        "OS command interpreter."
                    ),
                    evidence=(
                        f"payload={sleep_payload!r}; SleepMedian={sleep_median:.2f}s, "
                        f"ControlMedian={zero_median:.2f}s, BaselineMedian={baseline_median:.2f}s, "
                        f"Threshold={threshold:.2f}s"
                    ),
                    detector=self.name,
                    confidence="medium",
                    references=["https://portswigger.net/web-security/os-command-injection"],
                )
        return None

    def _oast_probe(self, param, context, send, report_url, report_param) -> List[Finding]:
        oast = getattr(context, "oast", None)
        if oast is None or not getattr(oast, "enabled", False):
            return []
        correlation_id = f"cmdi|{report_url}|{param}"
        host = oast.new_payload_host(correlation_id)
        if not host:
            return []
        for template in CMDI_OAST_TEMPLATES:
            send(template.format(host=host))
        return [
            Finding(
                vulnerability="Blind OS Command Injection Probe Dispatched",
                severity="info",
                cwe="CWE-78",
                owasp="A03:2021 Injection",
                url=report_url,
                parameter=report_param,
                description=(
                    "Out-of-band command-injection payloads were sent. Confirm exploitation by "
                    "checking your collaborator/OAST listener for a DNS/HTTP interaction from "
                    "this callback host."
                ),
                evidence=f"callback_host={host}; correlation={correlation_id}",
                detector=self.name,
                confidence="low",
                references=["https://portswigger.net/web-security/os-command-injection/blind"],
            )
        ]

    def _sleep_templates(self, context: ScanContext) -> List[str]:
        templates = list(CMDI_SLEEP_TEMPLATES)
        # Fingerprint-driven tailoring: when a Windows stack is detected, try the
        # Windows-family payloads (ping -n / timeout) first so the likely-working
        # payload is reached sooner under a per-parameter payload cap.
        if self._windows_detected(context):
            windows = [t for t in templates if "ping -n" in t or "timeout" in t]
            unix = [t for t in templates if t not in windows]
            templates = windows + unix
        if context.cmdi_max_payloads > 0:
            return templates[: context.cmdi_max_payloads]
        return templates

    @staticmethod
    def _windows_detected(context: ScanContext) -> bool:
        markers = {"microsoft iis", "asp.net", "asp.net mvc", "kestrel (asp.net core)"}
        return any(str(t).lower() in markers for t in getattr(context, "technologies", []) or [])

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _timed_samples(request: Callable[[], object], count: int) -> Optional[Tuple[float, float]]:
        samples: List[float] = []
        for _ in range(max(1, count)):
            start = time.monotonic()
            response = request()
            elapsed = time.monotonic() - start
            if response is None:
                return None
            samples.append(elapsed)
        median = statistics.median(samples)
        abs_dev = [abs(x - median) for x in samples]
        mad = statistics.median(abs_dev) if abs_dev else 0.0
        return median, mad

    @staticmethod
    def _safe_get(engine: RequestEngine, url: str):
        try:
            return engine.get(url)
        except Exception:
            return None

    @staticmethod
    def _safe_submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        try:
            if method.upper() == "POST":
                return engine.post(action_url, data=data)
            return engine.get(action_url, params=data)
        except Exception:
            return None
