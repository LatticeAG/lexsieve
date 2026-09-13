"""Section 6.2: immutable baseline rules and pack extra rules.
Literal matching is case-folded through the normalized views with no
implicit word-boundary requirement; all occurrences are reported.
"""

import re

from .errors import ClosedError
from .jcs import is_obj
from .normalize import achar_text, match_to_spans, normalize_literal

CLASS_ORDER = [
    "override",
    "exfiltration",
    "tool_directive",
    "role_spoof",
    "encoding",
    "credential",
]

BASELINE = [
    {
        "id": "builtin.override",
        "cls": "override",
        "action": "strip",
        "literals": [
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore prior instructions",
            "disregard previous instructions",
        ],
    },
    {
        "id": "builtin.exfil",
        "cls": "exfiltration",
        "action": "hold",
        "literals": ["send the api key", "upload the secret", "exfiltrate"],
    },
    {
        "id": "builtin.tool",
        "cls": "tool_directive",
        "action": "hold",
        "literals": ["call the shell tool", "run this command", "invoke the payment tool"],
    },
    {
        "id": "builtin.role",
        "cls": "role_spoof",
        "action": "hold",
        "literals": ["<|system|>", "<|im_start|>system", "[system]"],
    },
    {
        "id": "builtin.credential",
        "cls": "credential",
        "action": "hold",
        "literals": ["authorization: bearer ", "-----begin private key-----"],
    },
]

_TAG_RE = re.compile(r"^[a-z][a-z0-9_.\-]{0,63}$")


def compile_baseline():
    return [
        {
            "id": r["id"],
            "cls": r["cls"],
            "action": r["action"],
            "alternatives": [[ord(c) for c in normalize_literal(l)] for l in r["literals"]],
        }
        for r in BASELINE
    ]


def _utf8(s):
    return s.encode("utf-8")


def compile_pack_rules(rules):
    """Validate a pack ExtraRule array (schema + section 8 bounds). Raises
    ClosedError INVALID_REQUEST on any violation; pack verify maps to
    SCHEMA."""
    if not isinstance(rules, list):
        raise ClosedError("INVALID_REQUEST", "rules not array")
    if len(rules) > 128:
        raise ClosedError("INVALID_REQUEST", "too many rules")
    ids = set()
    out = []
    prev_id = ""
    for rv in rules:
        if not is_obj(rv):
            raise ClosedError("INVALID_REQUEST", "rule not object")
        if sorted(rv.keys()) != ["action", "class", "id", "literals"]:
            raise ClosedError("INVALID_REQUEST", "rule members")
        rid, cls, action, literals = rv["id"], rv["class"], rv["action"], rv["literals"]
        if not isinstance(rid, str) or not _TAG_RE.match(rid) or not rid.startswith("pack."):
            raise ClosedError("INVALID_REQUEST", "bad rule id")
        if cls not in CLASS_ORDER:
            raise ClosedError("INVALID_REQUEST", "bad class")
        if action not in ("strip", "hold"):
            raise ClosedError("INVALID_REQUEST", "bad action")
        if action == "strip" and cls != "override":
            raise ClosedError("INVALID_REQUEST", "strip only for override")
        if cls != "override" and action != "hold":
            raise ClosedError("INVALID_REQUEST", "non-override must hold")
        if not isinstance(literals, list) or not (1 <= len(literals) <= 8):
            raise ClosedError("INVALID_REQUEST", "bad literals")
        norm_lits = []
        for l in literals:
            if not isinstance(l, str):
                raise ClosedError("INVALID_REQUEST", "literal not string")
            nl = normalize_literal(l)
            nb = len(nl.encode("utf-8"))
            if nb < 3 or nb > 128:
                raise ClosedError("INVALID_REQUEST", "literal size")
            norm_lits.append(nl)
        # canonical order required: unique, UTF-8 sorted
        sorted_lits = sorted(norm_lits, key=_utf8)
        for i in range(len(norm_lits)):
            if norm_lits[i] != sorted_lits[i]:
                raise ClosedError("INVALID_REQUEST", "literals not canonical order")
        if len(set(norm_lits)) != len(norm_lits):
            raise ClosedError("INVALID_REQUEST", "duplicate literal")
        if rid in ids:
            raise ClosedError("INVALID_REQUEST", "duplicate rule id")
        ids.add(rid)
        if out and rid <= prev_id:
            raise ClosedError("INVALID_REQUEST", "rules not sorted")
        prev_id = rid
        out.append(
            {
                "id": rid,
                "cls": cls,
                "action": action,
                "alternatives": [[ord(c) for c in l] for l in norm_lits],
            }
        )
    return out


# ---------------------------------------------------------------------------
# Literal matching over one normalized view.
# ---------------------------------------------------------------------------

def match_rule_in_view(view, alt, block_lens):
    n, m = len(view), len(alt)
    spans = []
    if m == 0 or n < m:
        return spans
    for i in range(0, n - m + 1):
        for j in range(m):
            if view[i + j].cp != alt[j]:
                break
        else:
            spans.extend(match_to_spans(view, i, i + m, block_lens))
    return spans


# ---------------------------------------------------------------------------
# Encoding predicate (spec 6.2). Runs on literal text, once-decoded text, and
# their one-space / no-separator concatenations — all pre case folding.
# ---------------------------------------------------------------------------

_B64 = frozenset(ord(c) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_B64U = frozenset(ord(c) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_HEXC = frozenset(ord(c) for c in "0123456789abcdefABCDEF")

_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64U_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64_decode(body, url_safe):
    alphabet = _B64U_CHARS if url_safe else _B64_CHARS
    acc = 0
    bits = 0
    out = []
    for cp in body:
        v = alphabet.find(chr(cp))
        if v < 0:
            return None
        acc = (acc << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def _b64_encode_nopad(data, url_safe):
    alphabet = _B64U_CHARS if url_safe else _B64_CHARS
    out = []
    for i in range(0, len(data), 3):
        b0 = data[i]
        b1 = data[i + 1] if i + 1 < len(data) else 0
        b2 = data[i + 2] if i + 2 < len(data) else 0
        n = (b0 << 16) | (b1 << 8) | b2
        out.append(alphabet[(n >> 18) & 63])
        out.append(alphabet[(n >> 12) & 63])
        if i + 1 < len(data):
            out.append(alphabet[(n >> 6) & 63])
        if i + 2 < len(data):
            out.append(alphabet[n & 63])
    return "".join(out)


def encoding_findings(inp, block_lens):
    """Runs the encoding predicate over one pre-fold annotated input.
    Returns one finding span per qualifying maximal run (hex + both base64
    alphabets share a run -> single finding over the whole run incl. any
    excluded suffix)."""
    n = len(inp)
    hits = []
    i = 0
    while i < n:
        c = inp[i]
        if c.b0 < 0:
            i += 1
            continue
        in_b64 = c.cp in _B64
        in_b64u = c.cp in _B64U
        in_hex = c.cp in _HEXC
        if not in_b64 and not in_b64u and not in_hex:
            i += 1
            continue

        def run_end(alpha):
            j = i
            while j < n and inp[j].b0 >= 0 and inp[j].cp in alpha:
                j += 1
            return j

        end_b64 = run_end(_B64) if in_b64 else i
        end_b64u = run_end(_B64U) if in_b64u else i
        end_hex = run_end(_HEXC) if in_hex else i
        max_end = max(end_b64, end_b64u, end_hex)
        qualified = False
        span_end = max_end  # code-unit span end in `inp`

        # hex predicate: even length >= 48; odd length -> longest even prefix
        hex_len = end_hex - i
        if hex_len >= 48:
            even_len = hex_len if hex_len % 2 == 0 else hex_len - 1
            if even_len >= 48:
                qualified = True
        # base64 / base64url predicates
        for end, url_safe in ((end_b64, False), (end_b64u, True)):
            run = inp[i:end]
            if len(run) < 32:
                continue
            body = [x.cp for x in run]
            if len(body) % 4 == 1:
                body = body[:-1]
            if len(body) < 32 or len(body) % 4 == 1:
                continue
            # required padding must follow the run in the source
            need = (4 - (len(body) % 4)) % 4
            pad_ok = True
            for p in range(need):
                if end + p >= n:
                    pad_ok = False
                    break
                ch = inp[end + p]
                if ch.cp != 0x3D or ch.b0 < 0:
                    pad_ok = False
                    break
            if not pad_ok:
                continue
            dec = _b64_decode(body, url_safe)
            if dec is None or len(dec) < 24:
                continue
            if _b64_encode_nopad(dec, url_safe) != "".join(chr(cp) for cp in body):
                continue
            qualified = True
            span_end = max(span_end, end + need)

        if qualified:
            # one finding over the whole maximal run including excluded suffixes
            last = max(span_end, max_end)
            for sp in match_to_spans(inp, i, last, block_lens):
                hits.append({"block": sp["block"], "start": sp["start"], "end": sp["end"]})
        i = max_end
    return hits


# ---------------------------------------------------------------------------
# Findings ordering / dedup (spec 6.1 end).
# ---------------------------------------------------------------------------

def finding_key(f):
    if f["span"] is None:
        return f"{f['rule_id']} {f['class']} ∅"
    sp = f["span"]
    return f"{f['rule_id']} {f['class']} {sp['block']} {sp['start']} {sp['end']}"


def dedup_sort_findings(fs):
    seen = {}
    for f in fs:
        k = finding_key(f)
        if k not in seen:
            seen[k] = f
    return sorted(seen.values(), key=_finding_sort_key)


def _finding_sort_key(f):
    sp = f["span"]
    if sp is None:
        return (1, 0, 0, 0, f["class"], f["rule_id"])
    return (0, sp["block"], sp["start"], sp["end"], f["class"], f["rule_id"])


FINDING_CAP = 64
