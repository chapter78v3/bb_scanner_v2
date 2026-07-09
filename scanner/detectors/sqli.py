from __future__ import annotations

import difflib
import statistics
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import (
    SQLI_BOOLEAN_PAIRS,
    SQLI_ERROR_PAYLOADS,
    SQLI_PARAM_HINTS,
    SQLI_TIME_DIFF_PAIRS,
    SQLI_TIME_PAYLOADS,
    match_sql_error,
)
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

# Boolean-based blind thresholds. A TRUE payload must render essentially the
# same page as the baseline, while a FALSE payload must diverge — and the
# divergence is re-confirmed with a second constant pair before reporting.
_BOOL_TRUE_SIM = 0.95
_BOOL_FALSE_SIM_MAX = 0.92
_BOOL_MIN_GAP = 0.05
_BOOL_SIM_MAXLEN = 12000


class SQLiDetector(DetectorPlugin):
    """Detects SQL injection via error-based, time-based, and boolean-blind checks."""

    name = "sqli"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        probes = context.metadata.setdefault("sqli_probe_artifacts", [])

        for url in context.crawl.urls:
            findings.extend(self._test_url_query_params(url, engine, context, probes))
            findings.extend(self._boolean_probe_url(url, engine, context, probes))

        for form in context.crawl.forms:
            findings.extend(self._test_form(form.action_url, form.method, form.fields, engine, context, probes))
            findings.extend(self._boolean_probe_form(form.action_url, form.method, form.fields, engine, context, probes))

        return findings

    def _test_url_query_params(self, url: str, engine: RequestEngine, context: ScanContext, probes: List[Dict[str, object]]) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        param_candidates = self._build_param_candidates(query_params, context)
        if not param_candidates:
            return findings

        for candidate_url in self._candidate_urls(parsed, context):
            baseline_stats, baseline_err = self._timed_get_samples(engine, candidate_url, context.sqli_baseline_samples)
            if baseline_stats is None:
                self._record_probe(
                    context,
                    probes,
                    {
                        "mode": "baseline",
                        "url": candidate_url,
                        "samples": context.sqli_baseline_samples,
                        "status": "error",
                        "error": "baseline request failed",
                        **(baseline_err or {}),
                    },
                )
                continue
            baseline_median, baseline_mad = baseline_stats
            self._record_probe(
                context,
                probes,
                {
                    "mode": "baseline",
                    "url": candidate_url,
                    "samples": context.sqli_baseline_samples,
                    "status": "ok",
                    "median": round(baseline_median, 4),
                    "mad": round(baseline_mad, 4),
                },
            )

            # Baseline body (unmodified params) so an error signature that is
            # ALWAYS present on the page cannot be mistaken for injection.
            baseline_body = self._safe_get_body(engine, self._with_params(candidate_url, query_params))
            baseline_body_l = (baseline_body or "").lower()

            for param in param_candidates:
                for payload in self._error_payloads(context):
                    mutated = dict(query_params)
                    mutated[param] = payload
                    test_url = self._with_params(candidate_url, mutated)
                    try:
                        response = engine.get(test_url)
                    except Exception as exc:
                        self._record_probe(
                            context,
                            probes,
                            {
                                "mode": "error",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "status": "error",
                                **self._error_details(exc),
                            },
                        )
                        continue
                    sig = match_sql_error(response.text)
                    marker = bool(sig) and (sig.lower() not in baseline_body_l)
                    if marker:
                        findings.append(
                            Finding(
                                vulnerability="SQL Injection (Error-based)",
                                severity="high",
                                cwe="CWE-89",
                                owasp="A03:2021 Injection",
                                url=test_url,
                                parameter=param,
                                description=(
                                    "A DBMS error signature appeared after the SQLi probe and "
                                    "was not present in the baseline response."
                                ),
                                evidence=f"signature={sig!r}; {self._truncate_evidence(response.text)}",
                                detector=self.name,
                                confidence="medium",
                            )
                        )
                        self._record_probe(
                            context,
                            probes,
                            {
                                "mode": "error",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "status_code": response.status_code,
                                "marker_match": True,
                                "signature": sig,
                            },
                        )
                        break
                    self._record_probe(
                        context,
                        probes,
                        {
                            "mode": "error",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "status_code": response.status_code,
                            "marker_match": False,
                            "signature": sig,
                        },
                    )

                for payload in self._time_payloads(context):
                    mutated = dict(query_params)
                    mutated[param] = payload
                    test_url = self._with_params(candidate_url, mutated)
                    test_stats, test_err = self._timed_get_samples(engine, test_url, context.sqli_test_samples)
                    if test_stats is None:
                        self._record_probe(
                            context,
                            probes,
                            {
                                "mode": "time",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "samples": context.sqli_test_samples,
                                "status": "error",
                                "error": "timing request failed",
                                **(test_err or {}),
                            },
                        )
                        continue
                    test_median, _ = test_stats
                    dynamic_threshold = max(context.sqli_time_threshold, baseline_mad * 5)
                    if test_median - baseline_median > dynamic_threshold:
                        findings.append(
                            Finding(
                                vulnerability="SQL Injection (Time-based)",
                                severity="high",
                                cwe="CWE-89",
                                owasp="A03:2021 Injection",
                                url=test_url,
                                parameter=param,
                                description="Response delay significantly increased after time-based SQL payload.",
                                evidence=(
                                    f"BaselineMedian={baseline_median:.2f}s, TestMedian={test_median:.2f}s, "
                                    f"Threshold={dynamic_threshold:.2f}s, Payload={payload}"
                                ),
                                detector=self.name,
                                confidence="low",
                            )
                        )
                        self._record_probe(
                            context,
                            probes,
                            {
                                "mode": "time",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "baseline_median": round(baseline_median, 4),
                                "test_median": round(test_median, 4),
                                "threshold": round(dynamic_threshold, 4),
                                "signal": "positive",
                            },
                        )
                        break
                    self._record_probe(
                        context,
                        probes,
                        {
                            "mode": "time",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "baseline_median": round(baseline_median, 4),
                            "test_median": round(test_median, 4),
                            "threshold": round(dynamic_threshold, 4),
                            "signal": "negative",
                        },
                    )

                for pair in self._time_diff_pairs(context):
                    true_url = self._with_params(candidate_url, {**query_params, param: pair["true"]})
                    false_url = self._with_params(candidate_url, {**query_params, param: pair["false"]})
                    true_stats, true_err = self._timed_get_samples(engine, true_url, context.sqli_test_samples)
                    false_stats, false_err = self._timed_get_samples(engine, false_url, context.sqli_test_samples)
                    if true_stats is None or false_stats is None:
                        self._record_probe(
                            context,
                            probes,
                            {
                                "mode": "time_diff",
                                "url": candidate_url,
                                "parameter": param,
                                "pair": pair["name"],
                                "samples": context.sqli_test_samples,
                                "status": "error",
                                "error": "true/false timing request failed",
                                "true_error": true_err,
                                "false_error": false_err,
                            },
                        )
                        continue
                    true_median, _ = true_stats
                    false_median, _ = false_stats
                    dynamic_threshold = max(context.sqli_time_threshold, baseline_mad * 5)
                    delta = true_median - false_median
                    positive = delta > dynamic_threshold
                    self._record_probe(
                        context,
                        probes,
                        {
                            "mode": "time_diff",
                            "url": candidate_url,
                            "parameter": param,
                            "pair": pair["name"],
                            "true_median": round(true_median, 4),
                            "false_median": round(false_median, 4),
                            "delta": round(delta, 4),
                            "threshold": round(dynamic_threshold, 4),
                            "signal": "positive" if positive else "negative",
                        },
                    )
                    if positive:
                        findings.append(
                            Finding(
                                vulnerability="SQL Injection (Time-based Differential)",
                                severity="high",
                                cwe="CWE-89",
                                owasp="A03:2021 Injection",
                                url=candidate_url,
                                parameter=param,
                                description="True/False timing differential indicates SQL expression control.",
                                evidence=(
                                    f"Pair={pair['name']}, TrueMedian={true_median:.2f}s, "
                                    f"FalseMedian={false_median:.2f}s, Delta={delta:.2f}s, "
                                    f"Threshold={dynamic_threshold:.2f}s"
                                ),
                                detector=self.name,
                                confidence="medium",
                            )
                        )
                        break

        return findings

    def _test_form(
        self,
        action_url: str,
        method: str,
        fields,
        engine: RequestEngine,
        context: ScanContext,
        probes: List[Dict[str, object]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not fields:
            return findings

        method = (method or "GET").upper()
        baseline_data = {field.name: (field.value or "test") for field in fields}

        # Statistical baseline (median + MAD) shared by every field on this form,
        # mirroring the query-parameter path so form injection points get the
        # same timing rigor instead of a single sample vs. a hardcoded delta.
        baseline_stats, baseline_err = self._timed_submit_samples(
            engine, action_url, method, baseline_data, context.sqli_baseline_samples
        )
        if baseline_stats is None:
            self._record_probe(
                context,
                probes,
                {
                    "target": "form",
                    "mode": "baseline",
                    "url": action_url,
                    "method": method,
                    "samples": context.sqli_baseline_samples,
                    "status": "error",
                    "error": "baseline submit failed",
                    **(baseline_err or {}),
                },
            )
            return findings
        baseline_median, baseline_mad = baseline_stats
        dynamic_threshold = max(context.sqli_time_threshold, baseline_mad * 5)
        self._record_probe(
            context,
            probes,
            {
                "target": "form",
                "mode": "baseline",
                "url": action_url,
                "method": method,
                "samples": context.sqli_baseline_samples,
                "status": "ok",
                "median": round(baseline_median, 4),
                "mad": round(baseline_mad, 4),
            },
        )

        # Baseline body (unmodified fields) for the error-absence check.
        _bb = self._submit(engine, action_url, method, baseline_data)
        baseline_body_l = _bb.text.lower() if _bb is not None else ""

        for field in fields:
            # --- Error-based ---
            for payload in self._error_payloads(context):
                data = dict(baseline_data)
                data[field.name] = payload
                response = self._submit(engine, action_url, method, data)
                if response is None:
                    self._record_probe(
                        context,
                        probes,
                        {
                            "target": "form",
                            "mode": "error",
                            "url": action_url,
                            "method": method,
                            "parameter": field.name,
                            "payload": payload,
                            "status": "error",
                        },
                    )
                    continue
                sig = match_sql_error(response.text)
                marker = bool(sig) and (sig.lower() not in baseline_body_l)
                self._record_probe(
                    context,
                    probes,
                    {
                        "target": "form",
                        "mode": "error",
                        "url": action_url,
                        "method": method,
                        "parameter": field.name,
                        "payload": payload,
                        "status_code": response.status_code,
                        "marker_match": marker,
                        "signature": sig,
                    },
                )
                if marker:
                    findings.append(
                        Finding(
                            vulnerability="SQL Injection (Error-based)",
                            severity="high",
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                            url=action_url,
                            parameter=field.name,
                            description=(
                                "A DBMS error signature appeared after the form probe and was "
                                "not present in the baseline response."
                            ),
                            evidence=f"signature={sig!r}; {self._truncate_evidence(response.text)}",
                            detector=self.name,
                            confidence="medium",
                        )
                    )
                    break

            # --- Time-based (single-delay) ---
            for payload in self._time_payloads(context):
                data = dict(baseline_data)
                data[field.name] = payload
                test_stats, test_err = self._timed_submit_samples(
                    engine, action_url, method, data, context.sqli_test_samples
                )
                if test_stats is None:
                    self._record_probe(
                        context,
                        probes,
                        {
                            "target": "form",
                            "mode": "time",
                            "url": action_url,
                            "method": method,
                            "parameter": field.name,
                            "payload": payload,
                            "samples": context.sqli_test_samples,
                            "status": "error",
                            "error": "timing submit failed",
                            **(test_err or {}),
                        },
                    )
                    continue
                test_median, _ = test_stats
                positive = test_median - baseline_median > dynamic_threshold
                self._record_probe(
                    context,
                    probes,
                    {
                        "target": "form",
                        "mode": "time",
                        "url": action_url,
                        "method": method,
                        "parameter": field.name,
                        "payload": payload,
                        "baseline_median": round(baseline_median, 4),
                        "test_median": round(test_median, 4),
                        "threshold": round(dynamic_threshold, 4),
                        "signal": "positive" if positive else "negative",
                    },
                )
                if positive:
                    findings.append(
                        Finding(
                            vulnerability="SQL Injection (Time-based)",
                            severity="high",
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                            url=action_url,
                            parameter=field.name,
                            description="Form response delay significantly increased after time-based SQL payload.",
                            evidence=(
                                f"BaselineMedian={baseline_median:.2f}s, TestMedian={test_median:.2f}s, "
                                f"Threshold={dynamic_threshold:.2f}s, Payload={payload}"
                            ),
                            detector=self.name,
                            confidence="low",
                        )
                    )
                    break

            # --- Time-based differential (strongest timing signal) ---
            for pair in self._time_diff_pairs(context):
                true_data = dict(baseline_data)
                true_data[field.name] = pair["true"]
                false_data = dict(baseline_data)
                false_data[field.name] = pair["false"]
                true_stats, true_err = self._timed_submit_samples(
                    engine, action_url, method, true_data, context.sqli_test_samples
                )
                false_stats, false_err = self._timed_submit_samples(
                    engine, action_url, method, false_data, context.sqli_test_samples
                )
                if true_stats is None or false_stats is None:
                    self._record_probe(
                        context,
                        probes,
                        {
                            "target": "form",
                            "mode": "time_diff",
                            "url": action_url,
                            "method": method,
                            "parameter": field.name,
                            "pair": pair["name"],
                            "samples": context.sqli_test_samples,
                            "status": "error",
                            "error": "true/false timing submit failed",
                            "true_error": true_err,
                            "false_error": false_err,
                        },
                    )
                    continue
                true_median, _ = true_stats
                false_median, _ = false_stats
                delta = true_median - false_median
                positive = delta > dynamic_threshold
                self._record_probe(
                    context,
                    probes,
                    {
                        "target": "form",
                        "mode": "time_diff",
                        "url": action_url,
                        "method": method,
                        "parameter": field.name,
                        "pair": pair["name"],
                        "true_median": round(true_median, 4),
                        "false_median": round(false_median, 4),
                        "delta": round(delta, 4),
                        "threshold": round(dynamic_threshold, 4),
                        "signal": "positive" if positive else "negative",
                    },
                )
                if positive:
                    findings.append(
                        Finding(
                            vulnerability="SQL Injection (Time-based Differential)",
                            severity="high",
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                            url=action_url,
                            parameter=field.name,
                            description="True/False timing differential indicates SQL expression control in a form field.",
                            evidence=(
                                f"Pair={pair['name']}, TrueMedian={true_median:.2f}s, "
                                f"FalseMedian={false_median:.2f}s, Delta={delta:.2f}s, "
                                f"Threshold={dynamic_threshold:.2f}s"
                            ),
                            detector=self.name,
                            confidence="medium",
                        )
                    )
                    break

        return findings

    @staticmethod
    def _submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        try:
            if method.upper() == "POST":
                return engine.post(action_url, data=data)
            return engine.get(action_url, params=data)
        except Exception:
            return None

    # -- Boolean-based blind ------------------------------------------------

    def _boolean_probe_url(self, url: str, engine: RequestEngine, context: ScanContext, probes: List[Dict[str, object]]) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        candidates = self._build_param_candidates(params, context)
        if not candidates:
            return findings
        for param in candidates:
            base_value = params.get(param, "1")

            def requester(value, p=param):
                mutated = dict(params)
                mutated[p] = value
                return self._safe_response(engine, self._with_params(url, mutated))

            finding = self._boolean_core(requester, base_value, context, probes, url, param, "url")
            if finding is not None:
                findings.append(finding)
        return findings

    def _boolean_probe_form(self, action_url: str, method: str, fields, engine: RequestEngine, context: ScanContext, probes: List[Dict[str, object]]) -> List[Finding]:
        findings: List[Finding] = []
        if not fields:
            return findings
        method = (method or "GET").upper()
        base = {field.name: (field.value or "1") for field in fields}
        for field in fields:
            base_value = base.get(field.name, "1")

            def requester(value, name=field.name):
                data = dict(base)
                data[name] = value
                return self._submit(engine, action_url, method, data)

            finding = self._boolean_core(requester, base_value, context, probes, action_url, field.name, "form")
            if finding is not None:
                findings.append(finding)
        return findings

    def _boolean_core(self, requester, base_value: str, context: ScanContext, probes, report_url: str, param: str, target: str) -> Optional[Finding]:
        baseline = requester(base_value)
        if baseline is None:
            return None
        base_text = baseline.text
        base_status = baseline.status_code

        for family in self._boolean_pairs(context):
            true_resp = requester(base_value + family["true"])
            false_resp = requester(base_value + family["false"])
            if true_resp is None or false_resp is None:
                continue
            signal, sbt, sbf = self._bool_signal(
                base_text, true_resp.text, false_resp.text,
                base_status, true_resp.status_code, false_resp.status_code,
            )
            self._record_probe(context, probes, {
                "target": target, "mode": "boolean", "url": report_url, "parameter": param,
                "family": family["name"], "sim_true": round(sbt, 3), "sim_false": round(sbf, 3),
                "signal": "candidate" if signal else "negative",
            })
            if not signal:
                continue

            # Re-confirm with a different constant pair to eliminate coincidental
            # content differences before reporting.
            vtrue = requester(base_value + family["verify_true"])
            vfalse = requester(base_value + family["verify_false"])
            if vtrue is None or vfalse is None:
                continue
            signal2, vbt, vbf = self._bool_signal(
                base_text, vtrue.text, vfalse.text,
                base_status, vtrue.status_code, vfalse.status_code,
            )
            self._record_probe(context, probes, {
                "target": target, "mode": "boolean_verify", "url": report_url, "parameter": param,
                "family": family["name"], "sim_true": round(vbt, 3), "sim_false": round(vbf, 3),
                "signal": "positive" if signal2 else "negative",
            })
            if signal2:
                return Finding(
                    vulnerability="SQL Injection (Boolean-based Blind)",
                    severity="high",
                    cwe="CWE-89",
                    owasp="A03:2021 Injection",
                    url=report_url,
                    parameter=param,
                    description=(
                        "TRUE and FALSE boolean payloads appended to this parameter produced "
                        "consistently different responses — the TRUE payload matched the baseline "
                        "while the FALSE payload diverged — and the behaviour was re-confirmed with a "
                        "second constant pair. This indicates the value is evaluated inside a SQL "
                        "statement (blind SQL injection)."
                    ),
                    evidence=(
                        f"family={family['name']}; sim(base,true)={sbt:.2f}, sim(base,false)={sbf:.2f}; "
                        f"verify sim(base,true)={vbt:.2f}, sim(base,false)={vbf:.2f}"
                    ),
                    detector=self.name,
                    confidence="high",
                )
        return None

    @staticmethod
    def _bool_signal(base_text, true_text, false_text, base_status, true_status, false_status) -> Tuple[bool, float, float]:
        sim_bt = SQLiDetector._similarity(base_text, true_text)
        sim_bf = SQLiDetector._similarity(base_text, false_text)
        content_signal = (
            sim_bt >= _BOOL_TRUE_SIM
            and sim_bf <= _BOOL_FALSE_SIM_MAX
            and (sim_bt - sim_bf) >= _BOOL_MIN_GAP
        )
        # Status divergence: TRUE keeps the baseline status while FALSE changes it
        # (e.g. 200 SUCCESS vs a 500 on a subquery cardinality error).
        status_signal = (
            true_status == base_status
            and false_status != base_status
            and false_status != 0
            and sim_bt >= _BOOL_TRUE_SIM
        )
        return (content_signal or status_signal), sim_bt, sim_bf

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        a = (a or "")[:_BOOL_SIM_MAXLEN]
        b = (b or "")[:_BOOL_SIM_MAXLEN]
        if not a and not b:
            return 1.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    @staticmethod
    def _boolean_pairs(context: ScanContext) -> List[Dict[str, str]]:
        pairs = SQLI_BOOLEAN_PAIRS
        if context.sqli_max_payloads > 0:
            return pairs[: max(1, context.sqli_max_payloads)]
        return pairs

    @staticmethod
    def _safe_response(engine: RequestEngine, url: str):
        try:
            return engine.get(url)
        except Exception:
            return None

    @staticmethod
    def _safe_get_body(engine: RequestEngine, url: str):
        try:
            return engine.get(url).text
        except Exception:
            return None

    @staticmethod
    def _timed_get_samples(engine: RequestEngine, url: str, samples_count: int):
        samples: List[float] = []
        for _ in range(samples_count):
            start = time.monotonic()
            try:
                engine.get(url)
            except Exception as exc:
                return None, SQLiDetector._error_details(exc)
            samples.append(time.monotonic() - start)
        if not samples:
            return None, {"error": "no timing samples collected"}
        median = statistics.median(samples)
        abs_dev = [abs(x - median) for x in samples]
        mad = statistics.median(abs_dev) if abs_dev else 0.0
        return (median, mad), None

    @staticmethod
    def _timed_submit_samples(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str], samples_count: int):
        """Collect timing samples for a form submission; return (median, mad).

        Mirrors ``_timed_get_samples`` but is method-aware (GET params vs POST
        body) so form injection points get the same statistical treatment as
        query parameters.
        """
        samples: List[float] = []
        is_post = method.upper() == "POST"
        for _ in range(samples_count):
            start = time.monotonic()
            try:
                if is_post:
                    engine.post(action_url, data=data)
                else:
                    engine.get(action_url, params=data)
            except Exception as exc:
                return None, SQLiDetector._error_details(exc)
            samples.append(time.monotonic() - start)
        if not samples:
            return None, {"error": "no timing samples collected"}
        median = statistics.median(samples)
        abs_dev = [abs(x - median) for x in samples]
        mad = statistics.median(abs_dev) if abs_dev else 0.0
        return (median, mad), None

    @staticmethod
    def _error_details(exc: Exception) -> Dict[str, str]:
        return {
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
        }

    @staticmethod
    def _truncate_evidence(text: str, max_chars: int = 220) -> str:
        compact = " ".join(text.split())
        return compact[:max_chars]

    def _build_param_candidates(self, existing_params: Dict[str, str], context: ScanContext) -> List[str]:
        candidates = list(existing_params.keys())
        if not existing_params and context.sqli_aggressive:
            candidates.extend(sorted(SQLI_PARAM_HINTS))
        for custom in context.sqli_custom_params:
            if custom not in candidates:
                candidates.append(custom)
        return candidates

    def _candidate_urls(self, parsed, context: ScanContext) -> List[str]:
        base = urlunparse(parsed._replace(params=""))
        candidates = [base]
        if context.sqli_matrix_bypass:
            matrix_path = f"{parsed.path};.css;"
            matrix_url = urlunparse(parsed._replace(path=matrix_path, params=""))
            if matrix_url not in candidates:
                candidates.append(matrix_url)
        return candidates

    @staticmethod
    def _with_params(base_url: str, params: Dict[str, str]) -> str:
        parsed = urlparse(base_url)
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    @staticmethod
    def _error_payloads(context: ScanContext) -> List[str]:
        payloads = SQLI_ERROR_PAYLOADS
        if context.sqli_max_payloads > 0:
            return payloads[: context.sqli_max_payloads]
        return payloads

    @staticmethod
    def _time_payloads(context: ScanContext) -> List[str]:
        payloads = SQLI_TIME_PAYLOADS
        if context.sqli_max_payloads > 0:
            return payloads[: context.sqli_max_payloads]
        return payloads

    @staticmethod
    def _time_diff_pairs(context: ScanContext) -> List[Dict[str, str]]:
        pairs = SQLI_TIME_DIFF_PAIRS
        if context.sqli_max_payloads > 0:
            return pairs[: context.sqli_max_payloads]
        return pairs

    @staticmethod
    def _record_probe(context: ScanContext, probes: List[Dict[str, object]], entry: Dict[str, object]) -> None:
        if len(probes) >= context.sqli_probe_log_limit:
            return
        probes.append(entry)
