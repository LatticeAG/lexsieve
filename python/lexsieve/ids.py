"""Locked ID prefixes for protocol 1 and suffix generation.
Every ID is `<prefix>_` + 21 nanoid characters from [A-Za-z0-9_-].
IDs are correlation labels, not bearer capabilities; case-sensitive compare.
"""

import re

from .crypto import nanoid21
from .errors import ClosedError

ID_PREFIXES = (
    "lsreq", "lsres", "lsdec", "lsrcp", "lsq",
    "lsten", "lsgw", "lsrun", "lscall", "lspack", "lskey", "lsbatch",
)

_SUFFIX_RE = re.compile(r"^[A-Za-z0-9_-]{21}$")


def is_valid_id(prefix, ident):
    return (
        isinstance(ident, str)
        and ident.startswith(prefix + "_")
        and _SUFFIX_RE.match(ident[len(prefix) + 1 :]) is not None
    )


def require_id(prefix, ident, what):
    if not is_valid_id(prefix, ident):
        raise ClosedError("INVALID_REQUEST", f"bad {what} id")
    return ident


class CsprngAllocator:
    """Sequential ID allocator. Production uses this CSPRNG allocator; the
    conformance harness injects the fixed fixture allocator (A, B, C ...)."""

    def next(self, prefix):
        return f"{prefix}_{nanoid21()}"


def csprng_allocator():
    return CsprngAllocator()
