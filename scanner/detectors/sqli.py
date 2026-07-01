from __future__ import annotations

import statistics
import time
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..payloads import SQL_ERROR_PATTERNS, SQLI_ERROR_PAYLOADS, SQLI_PARAM_HINTS, SQLI_TIME_DIFF_PAIRS, SQLI_TIME_PAYLOADS
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine


class SQLiDetector(DetectorPlugin):
    """Detects potential SQL injection via error-based and time-based checks."""

    name = "sqli"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        probes = context.metadata.setdefault("sqli_probe_artifacts", [])

        for url in context.crawl.urls:
            findings.extend(self._test_url_query_params(url, engine, context, probes))

        for form in context.crawl.forms:
            findings.extend(self._test_form(form.action_url, form.method, form.fields, engine))

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
                    body_l = response.text.lower()
                    if any(pattern in body_l for pattern in SQL_ERROR_PATTERNS):
                        findings.append(
                            Finding(
                                vulnerability="SQL Injection (Error-based)",
                                severity="high",
                                cwe="CWE-89",
                                owasp="A03:2021 Injection",
                                url=test_url,
                                parameter=param,
                                description="Response contains database error patterns after SQLi probe.",
                                evidence=self._truncate_evidence(response.text),
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

    def _test_form(self, action_url: str, method: str, fields, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        if not fields:
            return findings

        baseline_data = {field.name: (field.value or "test") for field in fields}
        baseline = self._timed_submit(engine, action_url, method, baseline_data)

        for field in fields:
            for payload in SQLI_ERROR_PAYLOADS:
                data = dict(baseline_data)
                data[field.name] = payload
                response = self._submit(engine, action_url, method, data)
                if response is None:
                    continue
                body_l = response.text.lower()
                if any(pattern in body_l for pattern in SQL_ERROR_PATTERNS):
                    findings.append(
                        Finding(
                            vulnerability="SQL Injection (Error-based)",
                            severity="high",
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                            url=action_url,
                            parameter=field.name,
                            description="Form response indicates SQL error after probe.",
                            evidence=self._truncate_evidence(response.text),
                            detector=self.name,
                            confidence="medium",
                        )
                    )
                    break

            if baseline is not None:
                for payload in SQLI_TIME_PAYLOADS:
                    data = dict(baseline_data)
                    data[field.name] = payload
                    elapsed = self._timed_submit(engine, action_url, method, data)
                    if elapsed is not None and elapsed - baseline > 2.2:
                        findings.append(
                            Finding(
                                vulnerability="SQL Injection (Time-based)",
                                severity="high",
                                cwe="CWE-89",
                                owasp="A03:2021 Injection",
                                url=action_url,
                                parameter=field.name,
                                description="Form response delay increased after time-based SQL payload.",
                                evidence=f"Baseline={baseline:.2f}s, Test={elapsed:.2f}s, Payload={payload}",
                                detector=self.name,
                                confidence="low",
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
    def _error_details(exc: Exception) -> Dict[str, str]:
        return {
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
        }

    @staticmethod
    def _timed_submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        start = time.monotonic()
        try:
            if method.upper() == "POST":
                engine.post(action_url, data=data)
            else:
                engine.get(action_url, params=data)
        except Exception:
            return None
        return time.monotonic() - start

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
