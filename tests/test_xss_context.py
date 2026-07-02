"""Context-classification and breakout-survival tests for the XSS detector.

These lock in the false-positive fixes: input that is reflected but encoded, or
reflected in a non-executable context, must NOT be treated as an exploitable
candidate. Pure-function tests, no network or browser required.
"""
from scanner.detectors.xss import XSSDetector as X, _BREAKOUT_CHARS

TOKEN = "bbxdeadbeef01"
SENTINEL, GUARDS = X._make_sentinel(TOKEN)

_ENC = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _encode_all(s):
    for c, e in _ENC.items():
        s = s.replace(c, e)
    return s


def _strip_all(s):
    for c in _ENC:
        s = s.replace(c, "")
    return s


def _profile(body):
    idx = body.find(GUARDS[0])
    ctx = X._classify_context(body, idx)
    surv = X._breakout_survival(body, GUARDS)
    return ctx, X._is_candidate(ctx, surv)


# --- must NOT be candidates (these were the old false positives) ------------

def test_html_text_encoded_is_not_candidate():
    ctx, cand = _profile(f"<p>{_encode_all(SENTINEL)}</p>")
    assert ctx == "html_text" and cand is False


def test_double_quoted_attr_encoded_is_not_candidate():
    ctx, cand = _profile(f'<input value="{_encode_all(SENTINEL)}">')
    assert ctx == "attribute_double" and cand is False


def test_textarea_encoded_is_not_candidate():
    ctx, cand = _profile(f"<textarea>{_encode_all(SENTINEL)}</textarea>")
    assert ctx == "rcdata" and cand is False


def test_comment_encoded_is_not_candidate():
    ctx, cand = _profile(f"<!-- {_encode_all(SENTINEL)} -->")
    assert ctx == "comment" and cand is False


def test_stripped_input_is_not_candidate():
    ctx, cand = _profile(f"<p>{_strip_all(SENTINEL)}</p>")
    assert cand is False


def test_page_markup_does_not_leak_into_survival():
    # Encoded value immediately followed by real markup ("> and </p>): the
    # guarded slots must not pick up those literal chars.
    surv = X._breakout_survival(f'<input value="{_encode_all(SENTINEL)}"></input>', GUARDS)
    assert not any(surv.values())


# --- must be candidates (genuine reflected XSS) -----------------------------

def test_html_text_raw_is_candidate():
    ctx, cand = _profile(f"<p>{SENTINEL}</p>")
    assert ctx == "html_text" and cand is True


def test_double_quoted_attr_raw_is_candidate():
    ctx, cand = _profile(f'<input value="{SENTINEL}">')
    assert ctx == "attribute_double" and cand is True


def test_script_context_raw_is_candidate():
    ctx, cand = _profile(f'<script>var a="{SENTINEL}";</script>')
    assert ctx == "script" and cand is True


def test_partial_encode_quote_survives_is_candidate():
    # Only <> encoded; the surviving quote still allows attribute breakout.
    val = SENTINEL.replace("<", _ENC["<"]).replace(">", _ENC[">"])
    ctx, cand = _profile(f'<input value="{val}">')
    assert ctx == "attribute_double" and cand is True
