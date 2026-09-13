"""Section 5: adapter extraction and serialization for native, MCP, and
OpenAI surfaces. All pre-candidate failures are closed errors (no Decision,
no receipt). The FailureEnvelope replaces the return on wire-level
failures; it carries no tool bytes.
"""

from .errors import ClosedError
from .jcs import is_obj, jcs, parse_json

WIRE_CAP = 262144
TEXT_CAP = 32768
COMPLETION_TIMEOUT_MS = 5000

FAILURE_ENVELOPE = {
    "type": "lexsieve.tool-unavailable.v1",
    "trust": "untrusted",
    "notice": "Tool result unavailable.",
}


def failure_envelope_json():
    return jcs(FAILURE_ENVELOPE)


def decode_wire(data):
    """Strict UTF-8 decode of wire bytes; invalid input -> INVALID_UTF8."""
    try:
        return bytes(data).decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise ClosedError("INVALID_UTF8", "wire bytes not UTF-8") from None


# --- native -----------------------------------------------------------------
# The native adapter receives the already-decoded text blocks from the host
# SDK, builds a Candidate with trusted metadata supplied by the caller.
def native_extract(texts):
    blocks = [{"index": i, "text": t} for i, t in enumerate(texts)]
    check_block_bounds(blocks)
    return blocks


def check_block_bounds(blocks):
    if not (1 <= len(blocks) <= 8):
        raise ClosedError("LIMIT", "block count")
    total = 0
    for b in blocks:
        n = len(b["text"].encode("utf-8"))
        if n > TEXT_CAP:
            raise ClosedError("LIMIT", "block size")
        total += n
    if total > TEXT_CAP:
        raise ClosedError("LIMIT", "total size")


# --- MCP --------------------------------------------------------------------
# Accepts exactly content, optional structuredContent, optional isError,
# optional _meta at the result level.
def mcp_extract(result):
    if not is_obj(result):
        raise ClosedError("UNSUPPORTED_CONTENT", "mcp result")
    o = result
    for k in o:
        if k not in ("content", "structuredContent", "isError", "_meta"):
            raise ClosedError("UNSUPPORTED_CONTENT", f"unexpected member {k}")
    if "content" not in o:
        raise ClosedError("UNSUPPORTED_CONTENT", "missing content")
    if "isError" in o:
        is_error = o["isError"]
        if not isinstance(is_error, bool):
            raise ClosedError("UNSUPPORTED_CONTENT", "isError not boolean")
    else:
        is_error = None
    content = o["content"]
    if not isinstance(content, list) or not (1 <= len(content) <= 8):
        raise ClosedError("UNSUPPORTED_CONTENT", "content shape")
    texts = []
    for item in content:
        if not is_obj(item):
            raise ClosedError("UNSUPPORTED_CONTENT", "content item")
        if sorted(item.keys()) != ["text", "type"]:
            raise ClosedError("UNSUPPORTED_CONTENT", "content members")
        if item["type"] != "text":
            raise ClosedError("UNSUPPORTED_CONTENT", "content type")
        if not isinstance(item["text"], str):
            raise ClosedError("UNSUPPORTED_CONTENT", "text type")
        texts.append(item["text"])
    if "structuredContent" in o:
        sc = o["structuredContent"]
        if not is_obj(sc):
            raise ClosedError("UNSUPPORTED_CONTENT", "structuredContent not object")
        # parsed under the embedded-JSON rules; becomes a final text block of
        # its JCS serialization
        texts.append(jcs(sc))
    blocks = [{"index": i, "text": t} for i, t in enumerate(texts)]
    check_block_bounds(blocks)
    return {"blocks": blocks, "toolError": is_error is True}


def mcp_serialize(envelope, tool_error):
    """The MCP return serializer replaces the complete result; isError is
    true for tool_error or hold."""
    return {
        "content": [{"type": "text", "text": jcs(envelope)}],
        "isError": bool(tool_error) or envelope["disposition"] == "hold",
    }


def mcp_serialize_failure():
    return {
        "content": [{"type": "text", "text": failure_envelope_json()}],
        "isError": True,
    }


# --- OpenAI -------------------------------------------------------------------
def openai_extract(output):
    if not isinstance(output, str):
        raise ClosedError("UNSUPPORTED_CONTENT", "output not string")
    blocks = [{"index": 0, "text": output}]
    check_block_bounds(blocks)
    return {"blocks": blocks, "toolError": False}


def openai_serialize(envelope, tool_call_id):
    return {"role": "tool", "tool_call_id": tool_call_id, "content": jcs(envelope)}


def openai_serialize_failure(tool_call_id):
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": failure_envelope_json(),
    }


# --- wire-cap framing (section 5.3) -------------------------------------------

def receive_wire(data):
    """Validates raw wire bytes against the transport cap and UTF-8, then
    parses to JSON for the MCP adapter path. Returns the decoded text."""
    if len(data) > WIRE_CAP:
        raise ClosedError("LIMIT", "wire cap")
    return decode_wire(data)
