"""Section 6.1: normalized views and origin maps.

Every normalized character carries an origin interval in (block, byte)
space: [b0,s0) .. [b1,e1). For a single-block interval b0==b1. Synthetic
concat separators carry b0=-1 (no origin). A match maps back to the
smallest original interval covering its contributing bytes in each block,
including intervening removed controls.

Code-unit handling mirrors the TypeScript implementation: decode_pass walks
the block text as UTF-16 code units (JS string semantics), so an astral
literal occupies two slots exactly as it does in the reference engine.
"""

import unicodedata

from .jcs import parse_json_aux, JsonLimitError, utf16_units
from .unicode import (
    case_fold_cp,
    grapheme_clusters,
    is_default_ignorable,
    is_white_space,
)


class HoldSignal(Exception):
    """Mid-screening conditions that still produce a committed hold Decision."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason  # 'LIMIT' | 'INVALID_UTF8'


class AChar:
    __slots__ = ("cp", "b0", "s0", "b1", "e1")

    def __init__(self, cp, b0, s0, b1, e1):
        self.cp = cp
        self.b0 = b0
        self.s0 = s0
        self.b1 = b1
        self.e1 = e1


SYNTH = (-1, 0, -1, 0)


def achar_text(chars):
    return "".join(chr(c.cp) for c in chars)


def utf8_byte_spans(text):
    """Byte offset of each code point in `text` (UTF-8). Returns list indexed
    by code-point ordinal -> (byteStart, byteEnd)."""
    spans = []
    b = 0
    for ch in text:
        n = len(ch.encode("utf-8"))
        spans.append((b, b + n))
        b += n
    return spans


# ---------------------------------------------------------------------------
# Decoding pass (view D input). One left-to-right source pass; generated
# characters are never rescanned.
# ---------------------------------------------------------------------------

_NAMED_ENTITIES = {"amp": 0x26, "lt": 0x3C, "gt": 0x3E, "quot": 0x22, "apos": 0x27}

_HEXD = frozenset("0123456789abcdefABCDEF")


def _is_hex_at(units, i):
    return i < len(units) and chr(units[i]) in _HEXD


def _cp_at(units, cu):
    c = units[cu]
    if 0xD800 <= c <= 0xDBFF:
        return 0x10000 + ((c - 0xD800) << 10) + (units[cu + 1] - 0xDC00)
    return c


def decode_pass(text, block_idx, byte_spans, cu_to_cp, string_spans):
    """Decodes `text` into annotated chars. `string_spans` are code-unit
    spans of JSON string content when the whole block is a complete JSON
    value; escapes decode only inside them. `block_idx` is the block index
    for origins."""
    units = utf16_units(text)
    n = len(units)

    def ustr(i, j):
        return "".join(chr(c) for c in units[i:j])

    def cp_at_idx(i):
        return _cp_at(units, i)

    out = []

    def lit(cp_idx, s, e):
        # Mirrors the TS reference: the ordinal is passed to a code-unit
        # indexing helper; identical behavior including astral handling.
        out.append(AChar(cp_at_idx(cp_idx), block_idx, s, block_idx, e))

    # string_spans sorted; pointer
    sp = 0

    def in_string(cu):
        nonlocal sp
        while sp < len(string_spans) and string_spans[sp][1] <= cu:
            sp += 1
        return (
            sp < len(string_spans)
            and string_spans[sp][0] <= cu < string_spans[sp][1]
        )

    i = 0
    while i < n:
        c = units[i]
        cp_ord = cu_to_cp[i]
        bs, be = byte_spans[cp_ord]

        if c == 0x5C and string_spans is not None and in_string(i):
            # JSON escape inside a string token
            e = units[i + 1] if i + 1 < n else -1

            def esc_bytes(k):
                first = byte_spans[cu_to_cp[i]]
                last = byte_spans[cu_to_cp[i + k - 1]]
                return (first[0], last[1])

            consumed = 0
            cp = -1
            if e == 0x22:
                cp, consumed = 0x22, 2
            elif e == 0x5C:
                cp, consumed = 0x5C, 2
            elif e == 0x2F:
                cp, consumed = 0x2F, 2
            elif e == 0x62:
                cp, consumed = 0x08, 2
            elif e == 0x66:
                cp, consumed = 0x0C, 2
            elif e == 0x6E:
                cp, consumed = 0x0A, 2
            elif e == 0x72:
                cp, consumed = 0x0D, 2
            elif e == 0x74:
                cp, consumed = 0x09, 2
            elif e == 0x75:
                h1 = ustr(i + 2, i + 6)
                if len(h1) == 4 and all(ch in _HEXD for ch in h1):
                    v1 = int(h1, 16)
                    if 0xD800 <= v1 <= 0xDBFF:
                        h2 = ustr(i + 8, i + 12)
                        if (
                            i + 7 < n
                            and units[i + 6] == 0x5C
                            and units[i + 7] == 0x75
                            and len(h2) == 4
                            and all(ch in _HEXD for ch in h2)
                        ):
                            v2 = int(h2, 16)
                            if 0xDC00 <= v2 <= 0xDFFF:
                                cp = 0x10000 + ((v1 - 0xD800) << 10) + (v2 - 0xDC00)
                                consumed = 12
                    elif not (0xDC00 <= v1 <= 0xDFFF):
                        cp = v1
                        consumed = 6
            if consumed > 0 and cp >= 0:
                s, e2 = esc_bytes(consumed)
                out.append(AChar(cp, block_idx, s, block_idx, e2))
                i += consumed
                continue
            lit(cp_ord, bs, be)
            i += 1
            continue

        if c == 0x26:
            # & entity — longest applicable = must end at ';'
            semi = -1
            j = i + 1
            while j < n:
                if units[j] == 0x3B:
                    semi = j
                    break
                j += 1
            if semi > i + 1 and semi - i <= 32:
                name = ustr(i + 1, semi)
                cp = -1
                if name in _NAMED_ENTITIES:
                    cp = _NAMED_ENTITIES[name]
                elif name.startswith("#x") or name.startswith("#X"):
                    d = name[2:]
                    if d and all(ch in _HEXD for ch in d):
                        cp = int(d, 16)
                elif name.startswith("#"):
                    d = name[1:]
                    if d.isdigit():
                        cp = int(d, 10)
                if 0 <= cp <= 0x10FFFF and not (0xD800 <= cp <= 0xDFFF):
                    s = byte_spans[cu_to_cp[i]][0]
                    e2 = byte_spans[cu_to_cp[semi]][1]
                    out.append(AChar(cp, block_idx, s, block_idx, e2))
                    i = semi + 1
                    continue
            lit(cp_ord, bs, be)
            i += 1
            continue

        if c == 0x25 and i + 2 < n and _is_hex_at(units, i + 1) and _is_hex_at(units, i + 2):
            # maximal run of %XX escapes
            j = i
            bytevals = []
            while (
                j + 2 < n
                and units[j] == 0x25
                and _is_hex_at(units, j + 1)
                and _is_hex_at(units, j + 2)
            ):
                bytevals.append(int(ustr(j + 1, j + 3), 16))
                j += 3
            run_end_cu = j  # exclusive
            s = byte_spans[cu_to_cp[i]][0]
            e2 = byte_spans[cu_to_cp[run_end_cu - 1]][1]
            try:
                decoded = bytes(bytevals).decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise HoldSignal("INVALID_UTF8") from None
            for ch in decoded:
                out.append(AChar(ord(ch), block_idx, s, block_idx, e2))
            i = run_end_cu
            continue

        lit(cp_ord, bs, be)
        i += 1
    return out


# ---------------------------------------------------------------------------
# Normalization: grapheme clusters -> NFKC -> casefold -> DICP removal ->
# whitespace collapse. Returns annotated output chars.
# ---------------------------------------------------------------------------

def normalize_chars(chars):
    cps = [c.cp for c in chars]
    clusters = grapheme_clusters(cps)
    out = []
    for cs, ce in clusters:
        cluster = chars[cs:ce]
        origin = (cluster[0].b0, cluster[0].s0, cluster[-1].b1, cluster[-1].e1)
        s = "".join(chr(c.cp) for c in cluster)
        nfkc = unicodedata.normalize("NFKC", s)
        for ch in nfkc:
            for fcp in case_fold_cp(ord(ch)):
                out.append(AChar(fcp, *origin))
    # remove Default_Ignorable_Code_Point
    no_ign = [c for c in out if not is_default_ignorable(c.cp)]
    # whitespace: map to ASCII space, collapse maximal runs
    collapsed = []
    run = None
    for c in no_ign:
        if is_white_space(c.cp):
            if run is not None:
                run.b1 = c.b1
                run.e1 = c.e1
                if c.b0 < run.b0 or run.b0 == -1:
                    run.b0 = c.b0
                    run.s0 = c.s0
            else:
                run = AChar(0x20, c.b0, c.s0, c.b1, c.e1)
        else:
            if run is not None:
                collapsed.append(run)
                run = None
            collapsed.append(c)
    if run is not None:
        collapsed.append(run)
    return collapsed


def normalize_literal(text):
    """Pure normalization of a literal string (pack rule compile path) — no
    origin tracking needed."""
    spans = utf8_byte_spans(text)
    chars = []
    for k, ch in enumerate(text):
        chars.append(AChar(ord(ch), 0, spans[k][0], 0, spans[k][1]))
    return achar_text(normalize_chars(chars))


def build_cu_to_cp(text):
    """Code-unit index -> code point ordinal map for a string. The low
    surrogate slot of a surrogate pair is left as None, mirroring the TS
    reference (a hole in the Array) — astral input is outside the screened
    profile."""
    units = utf16_units(text)
    m = [None] * len(units)
    i = 0
    ordinal = 0
    while i < len(units):
        m[i] = ordinal
        c = units[i]
        if 0xD800 <= c <= 0xDBFF:
            i += 1
        ordinal += 1
        i += 1
    return m


# ---------------------------------------------------------------------------
# Views per block + multi-block concatenations.
# ---------------------------------------------------------------------------

NORMALIZED_CAP = 262144


class BlockViews:
    __slots__ = ("literal", "decoded", "L", "D")

    def __init__(self, literal, decoded, L, D):
        self.literal = literal
        self.decoded = decoded
        self.L = L
        self.D = D


class CandidateViews:
    __slots__ = ("per_block", "rule_views", "predicate_inputs", "normalized_bytes")

    def __init__(self, per_block, rule_views, predicate_inputs, normalized_bytes):
        self.per_block = per_block
        self.rule_views = rule_views
        self.predicate_inputs = predicate_inputs
        self.normalized_bytes = normalized_bytes


def build_views(blocks):
    per_block = []
    normalized_bytes = 0
    for b in blocks:
        text = b["text"]
        byte_spans = utf8_byte_spans(text)
        cu_to_cp = build_cu_to_cp(text)
        literal = []
        for k, ch in enumerate(text):
            literal.append(
                AChar(ord(ch), b["index"], byte_spans[k][0], b["index"], byte_spans[k][1])
            )
        try:
            aux = parse_json_aux(text)
        except JsonLimitError:
            raise HoldSignal("LIMIT") from None
        decoded = decode_pass(text, b["index"], byte_spans, cu_to_cp, aux[1] if aux else None)
        L = normalize_chars(literal)
        D = normalize_chars(decoded)
        normalized_bytes += len(achar_text(L).encode("utf-8")) + len(
            achar_text(D).encode("utf-8")
        )
        per_block.append(BlockViews(literal, decoded, L, D))

    rule_views = []
    predicate_inputs = []
    for bv in per_block:
        rule_views.append(bv.L)
        rule_views.append(bv.D)
        predicate_inputs.append(bv.literal)
        predicate_inputs.append(bv.decoded)
    if len(per_block) > 1:
        for kind in ("L", "D"):
            joined_space = []
            joined_none = []
            for i, bv in enumerate(per_block):
                if i > 0:
                    joined_space.append(AChar(0x20, *SYNTH))
                joined_space.extend(getattr(bv, kind))
                joined_none.extend(getattr(bv, kind))
            rule_views.append(joined_space)
            rule_views.append(joined_none)
            normalized_bytes += len(achar_text(joined_space).encode("utf-8"))
            normalized_bytes += len(achar_text(joined_none).encode("utf-8"))
        for kind in ("literal", "decoded"):
            joined_space = []
            joined_none = []
            for i, bv in enumerate(per_block):
                if i > 0:
                    joined_space.append(AChar(0x20, *SYNTH))
                joined_space.extend(getattr(bv, kind))
                joined_none.extend(getattr(bv, kind))
            predicate_inputs.append(joined_space)
            predicate_inputs.append(joined_none)
    if normalized_bytes > NORMALIZED_CAP:
        raise HoldSignal("LIMIT")
    return CandidateViews(per_block, rule_views, predicate_inputs, normalized_bytes)


def match_to_spans(chars, i0, i1, block_lens):
    """Map a match over normalized chars [i0,i1) to per-block source
    intervals. `block_lens` gives the UTF-8 byte length of each block."""
    contrib = {}
    for i in range(i0, i1):
        c = chars[i]
        if c.b0 < 0:
            continue  # synthetic separator: no origin
        for b in range(c.b0, c.b1 + 1):
            s = c.s0 if b == c.b0 else 0
            e = c.e1 if b == c.b1 else (block_lens[b] if b < len(block_lens) else 0)
            cur = contrib.get(b)
            if cur is None:
                contrib[b] = [s, e]
            else:
                if s < cur[0]:
                    cur[0] = s
                if e > cur[1]:
                    cur[1] = e
    return [
        {"block": b, "start": se[0], "end": se[1]}
        for b, se in sorted(contrib.items())
    ]
