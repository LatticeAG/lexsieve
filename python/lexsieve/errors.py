"""Error codes and the two failure layers (spec section 3).

Closed errors (ClosedError) are raised before a valid Candidate exists or
when the engine cannot produce a signed Decision; they produce no receipt.
Hold reasons are committed Decision verdicts. Some names are shared between
the layers (LIMIT, UNSUPPORTED_CONTENT, INVALID_UTF8, DEADLINE); the layers
are distinguished by whether a committed Decision exists.
"""

RETRYABLE = frozenset(
    {"NOT_READY", "RATE_LIMITED", "CHAIN_GAP", "STORAGE_UNAVAILABLE", "DEADLINE"}
)


class ClosedError(Exception):
    """RPC-layer error carrying a protocol code."""

    def __init__(self, code, message=None):
        super().__init__(message if message is not None else code)
        self.code = code
        self.retryable = code in RETRYABLE


class NotImplementedError(Exception):
    """Hosted/paid surfaces outside the OSS core fail with this type."""


def rpc_error(code, request_id):
    return {
        "v": 1,
        "error": {"code": code, "retryable": code in RETRYABLE, "request_id": request_id},
    }
