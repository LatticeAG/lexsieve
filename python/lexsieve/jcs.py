"""RFC 8785 JCS canonicalization and the strict JSON parser used at every
LexSieve boundary. Wire profile (spec section 4): UTF-8 without BOM, no
duplicate object keys, no lone surrogates, no NaN/Infinity/-0, no
fractional numbers; numbers are safe integers.

The parser operates on UTF-16 code units so that recorded string-content
spans match the TypeScript implementation exactly.
"""

import re

from .errors import ClosedError

JsonValue = object  # documentation alias: str | int | bool | None | list | dict

HEX = "0123456789abcdef"
SAFE_INT_MAX = 9007199254740991


def escape_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif c == 0x08:
            out.append("\\b")
        elif c == 0x09:
            out.append("\\t")
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x0C:
            out.append("\\f")
        elif c == 0x0D:
            out.append("\\r")
        elif c < 0x20:
            out.append("\\u00" + HEX[(c >> 4) & 0xF] + HEX[c & 0xF])
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v):
    """Canonical JCS serialization. All numbers in the LexSieve wire profile
    are safe integers, so integer rendering is exact."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):  # bool handled above
        if abs(v) > SAFE_INT_MAX:
            raise ClosedError("INVALID_REQUEST", "non-integer in JCS")
        return str(v)
    if isinstance(v, float):
        raise ClosedError("INVALID_REQUEST", "non-integer in JCS")
    if isinstance(v, str):
        return escape_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(escape_string(k) + ":" + jcs(v[k]) for k in sorted(v.keys())) + "}"
    raise ClosedError("INVALID_REQUEST", "not a JSON value")


def jcs_bytes(v):
    return jcs(v).encode("utf-8")


class ParseLimits:
    __slots__ = ("max_depth", "max_nodes")

    def __init__(self, max_depth, max_nodes):
        self.max_depth = max_depth
        self.max_nodes = max_nodes


DEFAULT_PARSE_LIMITS = ParseLimits(512, 65536)
AUX_JSON_LIMITS = ParseLimits(16, 2048)


class JsonLimitError(Exception):
    """A bounded auxiliary parse crossed a declared limit."""


class JsonSyntaxError(Exception):
    pass


def utf16_units(s):
    """Python str -> list of UTF-16 code units (ints)."""
    b = s.encode("utf-16-be", "surrogatepass")
    return [(b[i] << 8) | b[i + 1] for i in range(0, len(b), 2)]


_NUM_RE = re.compile(r"-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?")
_HEX4_RE = re.compile(r"^[0-9a-fA-F]{4}$")


class _Parser:
    """Recursive-descent strict JSON parser over UTF-16 code units."""

    def __init__(self, text, limits, string_spans=None):
        self.units = utf16_units(text)
        self.limits = limits
        self.string_spans = string_spans
        self.pos = 0
        self.nodes = 0

    def parse(self):
        self._ws()
        v = self._value(0)
        self._ws()
        if self.pos != len(self.units):
            self._fail("trailing data")
        return v

    def _fail(self, why):
        raise JsonSyntaxError(f"{why} at {self.pos}")

    def _fail_limit(self, what):
        raise JsonLimitError(what)

    def _ws(self):
        u = self.units
        while self.pos < len(u) and u[self.pos] in (0x20, 0x09, 0x0A, 0x0D):
            self.pos += 1

    def _unit_str(self, i, j):
        return "".join(chr(c) for c in self.units[i:j])

    def _value(self, depth):
        if depth > self.limits.max_depth:
            self._fail_limit("depth")
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            self._fail_limit("nodes")
        if self.pos >= len(self.units):
            self._fail("unexpected end")
        c = self.units[self.pos]
        if c == 0x7B:
            return self._object(depth)
        if c == 0x5B:
            return self._array(depth)
        if c == 0x22:
            return self._string()
        if c == 0x74:
            return self._lit("true", True)
        if c == 0x66:
            return self._lit("false", False)
        if c == 0x6E:
            return self._lit("null", None)
        if c == 0x2D or 0x30 <= c <= 0x39:
            return self._number()
        self._fail("unexpected character")

    def _lit(self, word, val):
        if self._unit_str(self.pos, self.pos + len(word)) == word:
            self.pos += len(word)
            return val
        self._fail("bad literal")

    def _object(self, depth):
        self.pos += 1  # {
        obj = {}
        self._ws()
        if self.pos < len(self.units) and self.units[self.pos] == 0x7D:
            self.pos += 1
            return obj
        while True:
            self._ws()
            if self.pos >= len(self.units) or self.units[self.pos] != 0x22:
                self._fail("object key must be string")
            key = self._string()
            if key in obj:
                self._fail("duplicate key")
            self._ws()
            if self.pos >= len(self.units) or self.units[self.pos] != 0x3A:
                self._fail("expected :")
            self.pos += 1
            self._ws()
            obj[key] = self._value(depth + 1)
            self._ws()
            if self.pos >= len(self.units):
                self._fail("expected , or }")
            c = self.units[self.pos]
            if c == 0x2C:
                self.pos += 1
                continue
            if c == 0x7D:
                self.pos += 1
                return obj
            self._fail("expected , or }")

    def _array(self, depth):
        self.pos += 1  # [
        arr = []
        self._ws()
        if self.pos < len(self.units) and self.units[self.pos] == 0x5D:
            self.pos += 1
            return arr
        while True:
            self._ws()
            arr.append(self._value(depth + 1))
            self._ws()
            if self.pos >= len(self.units):
                self._fail("expected , or ]")
            c = self.units[self.pos]
            if c == 0x2C:
                self.pos += 1
                continue
            if c == 0x5D:
                self.pos += 1
                return arr
            self._fail("expected , or ]")

    def _string(self):
        self.pos += 1  # "
        content_start = self.pos
        out = []
        u = self.units
        n = len(u)
        while True:
            if self.pos >= n:
                self._fail("unterminated string")
            c = u[self.pos]
            if c == 0x22:
                if self.string_spans is not None:
                    self.string_spans.append((content_start, self.pos))
                self.pos += 1
                return "".join(out)
            if c < 0x20:
                self._fail("unescaped control in string")
            if c == 0x5C:
                self.pos += 1
                if self.pos >= n:
                    self._fail("unterminated escape")
                e = u[self.pos]
                self.pos += 1
                if e == 0x22:
                    out.append('"')
                elif e == 0x5C:
                    out.append("\\")
                elif e == 0x2F:
                    out.append("/")
                elif e == 0x62:
                    out.append("\b")
                elif e == 0x66:
                    out.append("\f")
                elif e == 0x6E:
                    out.append("\n")
                elif e == 0x72:
                    out.append("\r")
                elif e == 0x74:
                    out.append("\t")
                elif e == 0x75:
                    cp = self._hex4()
                    if 0xD800 <= cp <= 0xDBFF:
                        if (
                            self.pos + 1 < n
                            and u[self.pos] == 0x5C
                            and u[self.pos + 1] == 0x75
                        ):
                            self.pos += 2
                            lo = self._hex4()
                            if 0xDC00 <= lo <= 0xDFFF:
                                out.append(
                                    chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00))
                                )
                            else:
                                self._fail("lone high surrogate")
                        else:
                            self._fail("lone high surrogate")
                    elif 0xDC00 <= cp <= 0xDFFF:
                        self._fail("lone low surrogate")
                    else:
                        out.append(chr(cp))
                else:
                    self._fail("bad escape")
            elif 0xD800 <= c <= 0xDBFF and self.pos + 1 < n and 0xDC00 <= u[self.pos + 1] <= 0xDFFF:
                # paired surrogate halves -> single code point
                out.append(chr(0x10000 + ((c - 0xD800) << 10) + (u[self.pos + 1] - 0xDC00)))
                self.pos += 2
            else:
                out.append(chr(c))
                self.pos += 1

    def _hex4(self):
        if self.pos + 4 > len(self.units):
            self._fail("bad \\u escape")
        s = self._unit_str(self.pos, self.pos + 4)
        if not _HEX4_RE.match(s):
            self._fail("bad \\u escape")
        self.pos += 4
        return int(s, 16)

    def _number(self):
        m = _NUM_RE.match(self._unit_str(self.pos, len(self.units)))
        if not m:
            self._fail("bad number")
        tok = m.group(0)
        self.pos += len(tok)
        if "." in tok or "e" in tok or "E" in tok:
            f = float(tok)
            if not f.is_integer() or abs(f) > SAFE_INT_MAX:
                self._fail("number not a safe integer")
            if f == 0 and tok.startswith("-"):
                self._fail("negative zero")
            return int(f)
        n = int(tok)
        if abs(n) > SAFE_INT_MAX:
            self._fail("number not a safe integer")
        if tok == "-0":
            self._fail("negative zero")
        return n


def parse_json(source, limits=DEFAULT_PARSE_LIMITS):
    """Strict wire-profile JSON parse. `source` must already be validated
    UTF-8 text without BOM. All failures surface as ClosedError
    INVALID_REQUEST."""
    if source and source[0] == "﻿":
        raise ClosedError("INVALID_REQUEST", "BOM")
    try:
        return _Parser(source, limits).parse()
    except (JsonSyntaxError, JsonLimitError) as e:
        raise ClosedError("INVALID_REQUEST", f"json: {e}") from e


def parse_json_aux(source):
    """Auxiliary complete-JSON parse used by the decoding view (spec 6.1).
    Returns (value, string_spans) or None when the text is not a complete
    strict JSON value; raises JsonLimitError when the bounded-parse limits
    (16 levels, 2048 nodes) are crossed — the caller maps that to hold
    LIMIT."""
    if len(source) > 32768:
        return None
    string_spans = []
    try:
        value = _Parser(source, AUX_JSON_LIMITS, string_spans).parse()
        return (value, string_spans)
    except JsonSyntaxError:
        return None


def is_obj(v):
    return isinstance(v, dict)


def check_exact_keys(v, keys, what):
    for k in v:
        if k not in keys:
            raise ClosedError("INVALID_REQUEST", f"unknown member {k} in {what}")
    for k in keys:
        if k not in v:
            raise ClosedError("INVALID_REQUEST", f"missing member {k} in {what}")
