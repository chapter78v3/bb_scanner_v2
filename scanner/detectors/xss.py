from __future__ import annotations

import secrets
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Finding, ScanContext
from ..registry import DetectorPlugin
from ..request_engine import RequestEngine

# Metacharacters that must survive unencoded for an injection to break out of
# its surrounding context. Their survival is the core exploitability signal.
_BREAKOUT_CHARS = ("<", ">", '"', "'")

# Entity/encoded forms that indicate a breakout char was neutralized rather than
# passed through literally. Used only as a sanity aid; survival is measured
# positionally between alphanumeric guards, so page markup can never leak in.
_ENCODED_FORMS = {
    "<": ("&lt;", "&#60;", "&#x3c;"),
    ">": ("&gt;", "&#62;", "&#x3e;"),
    '"': ("&quot;", "&#34;", "&#x22;"),
    "'": ("&#39;", "&#x27;", "&apos;"),
}


class XSSDetector(DetectorPlugin):
    """Reflected XSS via context-aware reflection analysis + execution proof.

    Two stages, designed to cut the false positives that a naive
    ``payload in response.text`` check produces:

    1. Reflection & context probe (no browser). A unique token carrying raw
       breakout characters is injected. If it reflects, the detector classifies
       *where* it landed (HTML text, quoted/unquoted attribute, <script>,
       comment, <textarea>/<title>, <style>) and measures which breakout
       characters survived unencoded. A payload that reflects but whose
       breakout chars are entity-encoded, or that lands in a non-executable
       context, is NOT reported as high — that is exactly the old FP class.

    2. Execution confirmation (headless Chromium, GET only). When a renderer is
       available and stage 1 marks a reflection as a candidate, token-bearing
       payloads are navigated and a JS dialog carrying the token is awaited via
       ``renderer.probe_dom_xss``. A fired dialog is ground truth: high/high.
    """

    name = "xss"

    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        findings: List[Finding] = []
        renderer = self._usable_renderer(context)

        for url in context.crawl.urls:
            findings.extend(self._test_url(url, engine, context, renderer))

        for form in context.crawl.forms:
            findings.extend(
                self._test_form(form.action_url, form.method, form.fields, engine, context, renderer)
            )

        return findings

    # -- GET / query-parameter injection ---------------------------------

    def _test_url(self, url, engine, context, renderer) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return findings

        for param in params:
            finding = self._probe_param(parsed, params, param, engine, context, renderer, method="GET")
            if finding is not None:
                findings.append(finding)
        return findings

    # -- Form injection ---------------------------------------------------

    def _test_form(self, action_url, method, fields, engine, context, renderer) -> List[Finding]:
        findings: List[Finding] = []
        if not fields:
            return findings

        method = (method or "GET").upper()
        base = {f.name: (f.value or "scan") for f in fields}

        for field in fields:
            token = self._token()
            sentinel, guards = self._make_sentinel(token)
            data = dict(base)
            data[field.name] = sentinel
            response = self._submit(engine, action_url, method, data)
            if response is None:
                continue
            if "html" not in response.headers.get("Content-Type", ""):
                continue

            body = response.text
            idx = body.find(guards[0])
            if idx == -1:
                continue

            ctx = self._classify_context(body, idx)
            survival = self._breakout_survival(body, guards)

            # For GET forms we can confirm execution through the renderer by
            # replaying the submission as a query string. POST bodies can't be
            # driven by the URL-navigation probe, so they stay reflection-only.
            confirmed = False
            if renderer is not None and method == "GET":
                confirmed = self._confirm_execution_form(
                    action_url, base, field.name, ctx, engine, context, renderer
                )

            finding = self._build_finding(
                url=action_url,
                param=field.name,
                context_label=ctx,
                survival=survival,
                confirmed=confirmed,
                render_attempted=(renderer is not None and method == "GET"),
                post_only=(method != "GET"),
            )
            if finding is not None:
                findings.append(finding)
        return findings

    # -- Core per-parameter probe ----------------------------------------

    def _probe_param(self, parsed, params, param, engine, context, renderer, method) -> Optional[Finding]:
        token = self._token()
        sentinel, guards = self._make_sentinel(token)
        mutated = dict(params)
        mutated[param] = sentinel
        test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

        try:
            response = engine.get(test_url)
        except Exception:
            return None
        if "html" not in response.headers.get("Content-Type", ""):
            return None

        body = response.text
        idx = body.find(guards[0])
        if idx == -1:
            return None  # not reflected -> nothing to report

        ctx = self._classify_context(body, idx)
        survival = self._breakout_survival(body, guards)

        confirmed = False
        render_attempted = False
        if renderer is not None:
            candidate = self._is_candidate(ctx, survival)
            if candidate:
                render_attempted = True
                confirmed = self._confirm_execution_url(
                    parsed, params, param, ctx, context, renderer
                )

        return self._build_finding(
            url=test_url,
            param=param,
            context_label=ctx,
            survival=survival,
            confirmed=confirmed,
            render_attempted=render_attempted,
            post_only=False,
        )

    # -- Execution confirmation via headless browser ---------------------

    def _confirm_execution_url(self, parsed, params, param, ctx, context, renderer) -> bool:
        for payload in self._ordered_payloads(ctx):
            token = self._token()
            body = payload.replace("TOKEN", token)
            mutated = dict(params)
            mutated[param] = body
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            if self._fire(renderer, test_url, token, context):
                return True
        return False

    def _confirm_execution_form(self, action_url, base, field_name, ctx, engine, context, renderer) -> bool:
        parsed = urlparse(action_url)
        for payload in self._ordered_payloads(ctx):
            token = self._token()
            body = payload.replace("TOKEN", token)
            data = dict(base)
            data[field_name] = body
            test_url = urlunparse(parsed._replace(query=urlencode(data, doseq=True)))
            if self._fire(renderer, test_url, token, context):
                return True
        return False

    @staticmethod
    def _fire(renderer, url, token, context) -> bool:
        try:
            return bool(
                renderer.probe_dom_xss(
                    url,
                    token,
                    headers=None,
                    verify_tls=getattr(getattr(context, "oast", None), "verify_tls", True),
                )
            )
        except Exception:
            return False

    # -- Finding construction --------------------------------------------

    def _build_finding(
        self,
        url: str,
        param: str,
        context_label: str,
        survival: Dict[str, bool],
        confirmed: bool,
        render_attempted: bool,
        post_only: bool,
    ) -> Optional[Finding]:
        survived = [c for c in _BREAKOUT_CHARS if survival.get(c)]
        survived_str = "".join(survived) or "none"

        if confirmed:
            return Finding(
                vulnerability="Reflected XSS (execution-confirmed)",
                severity="high",
                cwe="CWE-79",
                owasp="A03:2021 Injection",
                url=url,
                parameter=param,
                description=(
                    "Injected payload executed in a headless browser: a JS dialog "
                    "fired carrying the unique probe token. This is a confirmed, "
                    "exploitable reflected XSS, not a raw reflection heuristic."
                ),
                evidence=f"context={context_label}; breakout_chars_survived={survived_str}; execution=confirmed",
                detector=self.name,
                confidence="high",
                references=["https://portswigger.net/web-security/cross-site-scripting/reflected"],
            )

        exploitable = self._is_candidate(context_label, survival)
        if exploitable:
            if render_attempted:
                note = (
                    "Execution was not observed in the headless browser (possible CSP, "
                    "a non-executing sink such as innerHTML with <script>, or timing). "
                    "Breakout characters survive unencoded, so manual verification is warranted."
                )
            elif post_only:
                note = (
                    "Reflected via a POST form in an executable context with unencoded "
                    "breakout characters. Headless execution confirmation is not attempted "
                    "for POST bodies; verify manually or with an authenticated browser session."
                )
            else:
                note = (
                    "Breakout characters survive unencoded in an executable context. "
                    "No headless renderer available to confirm execution (run with --render-js)."
                )
            return Finding(
                vulnerability="Reflected XSS (likely, unconfirmed)",
                severity="high",
                cwe="CWE-79",
                owasp="A03:2021 Injection",
                url=url,
                parameter=param,
                description=note,
                evidence=f"context={context_label}; breakout_chars_survived={survived_str}",
                detector=self.name,
                confidence="medium",
            )

        # Reflected, but the surrounding context encoded/neutralized the breakout
        # characters. Surface as informational for manual review — this does NOT
        # trip the high/critical exit code, and replaces the old false positive.
        return Finding(
            vulnerability="Reflected input (output-encoded, not exploitable here)",
            severity="info",
            cwe="CWE-79",
            owasp="A03:2021 Injection",
            url=url,
            parameter=param,
            description=(
                "Input is reflected in the response, but breakout characters are "
                "encoded or the reflection lands in a non-executable context "
                f"({context_label}). Not exploitable as-is; kept for manual review "
                "in case another sink or encoding path exists."
            ),
            evidence=f"context={context_label}; breakout_chars_survived={survived_str}",
            detector=self.name,
            confidence="low",
        )

    # -- Context classification & survival -------------------------------

    @staticmethod
    def _is_candidate(context_label: str, survival: Dict[str, bool]) -> bool:
        lt = survival.get("<", False)
        gt = survival.get(">", False)
        dq = survival.get('"', False)
        sq = survival.get("'", False)

        if context_label == "html_text":
            return lt and gt
        if context_label == "attribute_double":
            return dq or (lt and gt)
        if context_label == "attribute_single":
            return sq or (lt and gt)
        if context_label == "attribute_unquoted":
            return gt or dq or sq
        if context_label == "script":
            return lt or dq or sq  # close the tag, or break out of a JS string
        if context_label in ("rcdata", "comment", "style"):
            return lt and gt  # need to close the special context first
        return lt and gt  # unknown -> conservative

    @staticmethod
    def _breakout_survival(body: str, guards: List[str]) -> Dict[str, bool]:
        """Measure survival positionally between alphanumeric guards.

        The sentinel is g0 < g1 > g2 " g3 ' g4, where each gN is a unique
        alphanumeric token that passes through servers untouched. The content of
        each slot (between consecutive guards) is *exactly* what the server did
        to that one breakout character — literal means it survived, an entity
        means it was encoded, empty means it was stripped. Because the slots are
        bounded by guards, the page's own markup (</p>, "> etc.) can never leak
        into the measurement, which was the false-positive bug in the naive
        fixed-window approach.
        """
        survival = {c: False for c in _BREAKOUT_CHARS}

        # Locate every guard in order; bail to all-False if the reflection was
        # mangled (favor no false positive over a shaky signal).
        positions: List[int] = []
        cursor = 0
        for g in guards:
            pos = body.find(g, cursor)
            if pos == -1:
                return survival
            positions.append(pos)
            cursor = pos + len(g)

        for i, ch in enumerate(_BREAKOUT_CHARS):
            slot_start = positions[i] + len(guards[i])
            slot_end = positions[i + 1]
            slot = body[slot_start:slot_end]
            if ch in slot:
                survival[ch] = True  # passed through literally -> exploitable
            # else: encoded (entity present) or stripped (empty) -> not survived
        return survival

    @staticmethod
    def _classify_context(body: str, idx: int) -> str:
        low = body.lower()
        prefix = low[:idx]

        if prefix.rfind("<!--") > prefix.rfind("-->"):
            return "comment"

        def _open_gt_close(tag: str) -> bool:
            return XSSDetector._last_open(prefix, tag) > prefix.rfind("</" + tag)

        if _open_gt_close("script"):
            return "script"
        if _open_gt_close("style"):
            return "style"
        if _open_gt_close("textarea") or _open_gt_close("title"):
            return "rcdata"

        lt = prefix.rfind("<")
        gt = prefix.rfind(">")
        if lt > gt:  # sitting inside an unclosed tag => attribute context
            segment = body[lt:idx]
            if segment.count('"') % 2 == 1:
                return "attribute_double"
            if segment.count("'") % 2 == 1:
                return "attribute_single"
            return "attribute_unquoted"

        return "html_text"

    @staticmethod
    def _last_open(prefix_lower: str, tag: str) -> int:
        # Last position of "<tag" that opens an element (followed by space, >, or /).
        needle = "<" + tag
        pos = prefix_lower.rfind(needle)
        while pos != -1:
            nxt = prefix_lower[pos + len(needle): pos + len(needle) + 1]
            if nxt in ("", " ", ">", "/", "\t", "\n", "\r"):
                return pos
            pos = prefix_lower.rfind(needle, 0, pos)
        return -1

    # -- Payloads & helpers ----------------------------------------------

    @staticmethod
    def _ordered_payloads(context_label: str) -> List[str]:
        attr = [
            '"><img src=x onerror=alert(\'TOKEN\')>',
            "'><img src=x onerror=alert('TOKEN')>",
            '"><svg onload=alert(\'TOKEN\')>',
        ]
        html = [
            "<img src=x onerror=alert('TOKEN')>",
            "<svg onload=alert('TOKEN')>",
            "<script>alert('TOKEN')</script>",
        ]
        script = ["</script><img src=x onerror=alert('TOKEN')>", "';alert('TOKEN');//", '";alert(\'TOKEN\');//']
        special = ["--><img src=x onerror=alert('TOKEN')>", "</textarea><img src=x onerror=alert('TOKEN')>"]

        if context_label in ("attribute_double", "attribute_single", "attribute_unquoted"):
            return attr + html[:1]
        if context_label == "script":
            return script + html[:1]
        if context_label in ("comment", "rcdata", "style"):
            return special + html[:1]
        return html  # html_text / unknown

    @staticmethod
    def _usable_renderer(context: ScanContext):
        renderer = getattr(context, "renderer", None)
        if renderer is None:
            return None
        try:
            if hasattr(renderer, "is_available") and not renderer.is_available():
                return None
        except Exception:
            return None
        if not hasattr(renderer, "probe_dom_xss"):
            return None
        return renderer

    @staticmethod
    def _token() -> str:
        return "bbx" + secrets.token_hex(5)

    @staticmethod
    def _make_sentinel(token: str) -> Tuple[str, List[str]]:
        """Build a guarded probe: g0 < g1 > g2 " g3 ' g4.

        Guards are alphanumeric (server-safe) so each breakout character sits in
        its own precisely-bounded slot for survival measurement. Returns the
        sentinel string and the ordered list of guards.
        """
        guards = [f"{token}g{i}" for i in range(len(_BREAKOUT_CHARS) + 1)]
        parts: List[str] = [guards[0]]
        for i, ch in enumerate(_BREAKOUT_CHARS):
            parts.append(ch)
            parts.append(guards[i + 1])
        return "".join(parts), guards

    @staticmethod
    def _submit(engine: RequestEngine, action_url: str, method: str, data: Dict[str, str]):
        try:
            if method.upper() == "POST":
                return engine.post(action_url, data=data)
            return engine.get(action_url, params=data)
        except Exception:
            return None
