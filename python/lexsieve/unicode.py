"""Vendored Unicode 15.1.0 tables (scripts/gen_unicode_tables.mjs) plus the
grapheme cluster segmenter (UAX #29), full case folding (C+F mappings), and
the property lookups the screening pipeline needs. Unicode data is vendored
and pinned by digest per spec section 2; NFKC uses the host runtime's
unicodedata (UCD 15.0) and is the only non-vendored table — recorded in
STATUS.md.
"""

import json
import os

_path = os.path.join(os.path.dirname(__file__), "unicode_15_1.json")
with open(_path, "r", encoding="utf-8") as _f:
    _tables = json.load(_f)

UNICODE_VERSION = _tables["unicode"]
UNICODE_TABLE_SHA256 = "9442ce4c0e8e131200034e90ca568dc0b6255418db0fecdf29a83a78d73ee999"

_gcb = _tables["gcb"]
_ext_pict = _tables["extended_pictographic"]
_dicp_ranges = _tables["default_ignorable"]
_ws_ranges = _tables["white_space"]
_cat_letter = _tables["categories"]["letter"]
_cat_number = _tables["categories"]["number"]
_cat_pc = _tables["categories"]["connectorPunctuation"]
_casefold_map = _tables["casefold"]


def _in_ranges(ranges, cp):
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) >> 1
        r = ranges[mid]
        if cp < r[0]:
            hi = mid - 1
        elif cp > r[1]:
            lo = mid + 1
        else:
            return True
    return False


_GCB_ORDER = (
    "Prepend", "CR", "LF", "Control", "Extend", "Regional_Indicator",
    "SpacingMark", "L", "V", "T", "LV", "LVT", "ZWJ",
)


def gcb_of(cp):
    for prop in _GCB_ORDER:
        r = _gcb.get(prop)
        if r and _in_ranges(r, cp):
            return prop
    return "Other"


def is_extended_pictographic(cp):
    return _in_ranges(_ext_pict, cp)


def is_default_ignorable(cp):
    return _in_ranges(_dicp_ranges, cp)


def is_white_space(cp):
    return _in_ranges(_ws_ranges, cp)


def is_token_char(cp):
    return (
        _in_ranges(_cat_letter, cp)
        or _in_ranges(_cat_number, cp)
        or _in_ranges(_cat_pc, cp)
    )


def case_fold_cp(cp):
    """Full default case folding: CaseFolding.txt status C+F, vendored."""
    return _casefold_map.get(str(cp), [cp])


def case_fold_string(s):
    out = []
    for ch in s:
        for cp in case_fold_cp(ord(ch)):
            out.append(chr(cp))
    return "".join(out)


# --- UAX #29 extended grapheme cluster segmentation ------------------------

_GCB_CONTROLS = frozenset({"Control", "CR", "LF"})


def grapheme_clusters(cps):
    """Cluster boundaries: list of [start,end) index pairs over cps."""
    n = len(cps)
    out = []
    if n == 0:
        return out
    g = [gcb_of(c) for c in cps]
    start = 0
    # GB11 state: set when current position is after a ZWJ preceded by
    # ExtPict Extend*.
    ext_pict_before_zw_run = False
    ri_run = 1 if g[0] == "Regional_Indicator" else 0

    for i in range(1, n):
        prev, cur = g[i - 1], g[i]
        brk = True  # GB999 default
        if prev == "CR" and cur == "LF":
            brk = False  # GB3
        elif prev in _GCB_CONTROLS or cur in _GCB_CONTROLS:
            brk = True  # GB4/GB5
        elif prev == "L" and cur in ("L", "V", "LV", "LVT"):
            brk = False  # GB6
        elif prev in ("LV", "V") and cur in ("V", "T"):
            brk = False  # GB7
        elif prev in ("LVT", "T") and cur == "T":
            brk = False  # GB8
        elif cur == "Extend" or cur == "ZWJ":
            brk = False  # GB9
        elif cur == "SpacingMark":
            brk = False  # GB9a
        elif prev == "Prepend":
            brk = False  # GB9b
        elif prev == "ZWJ" and ext_pict_before_zw_run and is_extended_pictographic(cps[i]):
            brk = False  # GB11
        elif prev == "Regional_Indicator" and cur == "Regional_Indicator" and ri_run % 2 == 1:
            brk = False  # GB12/13

        if brk:
            out.append([start, i])
            start = i
        if cur == "ZWJ":
            j = i - 1
            while j >= start and g[j] == "Extend":
                j -= 1
            ext_pict_before_zw_run = j >= 0 and is_extended_pictographic(cps[j])
        elif cur != "Extend":
            ext_pict_before_zw_run = False
        ri_run = (
            (ri_run + 1) if prev == "Regional_Indicator" else 1
        ) if cur == "Regional_Indicator" else 0

    out.append([start, n])
    return out
