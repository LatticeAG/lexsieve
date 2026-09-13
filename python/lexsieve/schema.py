"""Section 4.1 + 7 + 8 + 11 wire schemas. Closed unions, exact members,
unknown members rejected at every level.

Wire values are plain Python objects: dict, list, str, int, bool, None.
"""

import re

from .errors import ClosedError
from .jcs import check_exact_keys, is_obj
from .ids import is_valid_id, require_id
from .model import validate_model_artifact

CLASSES = ["override", "exfiltration", "tool_directive", "role_spoof", "encoding", "credential"]
VERDICTS = ["pass", "strip", "hold"]
REASONS = [
    "CLEAN", "STRIPPED", "RULE_BLOCK", "MODEL_BLOCK", "MODEL_REQUIRED", "MODEL_TIMEOUT",
    "MODEL_INVALID", "LEXSHIELD_BLOCK", "LEXSHIELD_TIMEOUT", "LIMIT", "UNSUPPORTED_CONTENT",
    "INVALID_UTF8", "POLICY_CHANGED", "PACK_EXPIRED", "FINDING_LIMIT", "AUDIT_UNAVAILABLE",
    "DEADLINE",
]

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_B64U_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TAG_RE = re.compile(r"^[a-z][a-z0-9_.\-]{0,63}$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,128}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ORIGIN_RE = re.compile(r"^https://[^/?#]+$")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_hash(v):
    return isinstance(v, str) and _HASH_RE.match(v) is not None


def is_b64u(v, nbytes):
    import base64

    if not isinstance(v, str) or not _B64U_RE.match(v):
        return False
    try:
        dec = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    except Exception:
        return False
    return len(dec) == nbytes


def _is_pos_int(v):
    return _is_int(v) and v >= 1


def _is_nonneg_int(v):
    return _is_int(v) and v >= 0


def validate_binding(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "binding")
    o = v
    check_exact_keys(
        o,
        ["tenant_id", "gateway_id", "run_id", "call_id", "tool", "adapter", "result_ordinal"],
        "binding",
    )
    require_id("lsten", o["tenant_id"], "tenant_id")
    require_id("lsgw", o["gateway_id"], "gateway_id")
    require_id("lsrun", o["run_id"], "run_id")
    require_id("lscall", o["call_id"], "call_id")
    if not isinstance(o["tool"], str) or not _TOOL_RE.match(o["tool"]):
        raise ClosedError("INVALID_REQUEST", "tool")
    if o["adapter"] not in ("native", "mcp", "openai"):
        raise ClosedError("INVALID_REQUEST", "adapter")
    if not _is_nonneg_int(o["result_ordinal"]) or o["result_ordinal"] > 255:
        raise ClosedError("INVALID_REQUEST", "result_ordinal")
    return o


def validate_text_blocks(v):
    if not isinstance(v, list):
        raise ClosedError("INVALID_REQUEST", "blocks not array")
    if not (1 <= len(v) <= 8):
        raise ClosedError("INVALID_REQUEST", "block count")
    total = 0
    out = []
    for i, b in enumerate(v):
        if not is_obj(b):
            raise ClosedError("INVALID_REQUEST", "block not object")
        check_exact_keys(b, ["index", "text"], "block")
        if b["index"] != i:
            raise ClosedError("INVALID_REQUEST", "block index not contiguous")
        if not isinstance(b["text"], str):
            raise ClosedError("INVALID_REQUEST", "block text")
        nb = len(b["text"].encode("utf-8"))
        if nb > 32768:
            raise ClosedError("INVALID_REQUEST", "block size")
        total += nb
        out.append({"index": i, "text": b["text"]})
    if total > 32768:
        raise ClosedError("INVALID_REQUEST", "total size")
    return out


def validate_candidate(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "candidate")
    o = v
    check_exact_keys(o, ["result_id", "binding", "tool_error", "blocks"], "candidate")
    require_id("lsres", o["result_id"], "result_id")
    binding = validate_binding(o["binding"])
    if not isinstance(o["tool_error"], bool):
        raise ClosedError("INVALID_REQUEST", "tool_error")
    blocks = validate_text_blocks(o["blocks"])
    return {
        "result_id": o["result_id"],
        "binding": binding,
        "tool_error": o["tool_error"],
        "blocks": blocks,
    }


def validate_screen_request(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "screen request")
    o = v
    check_exact_keys(o, ["v", "request_id", "candidate"], "screen request")
    if o["v"] != 1:
        raise ClosedError("UNSUPPORTED_VERSION", "v")
    require_id("lsreq", o["request_id"], "request_id")
    candidate = validate_candidate(o["candidate"])
    return {"v": 1, "request_id": o["request_id"], "candidate": candidate}


def validate_snapshot(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "snapshot")
    o = v
    check_exact_keys(
        o, ["epoch", "config_hash", "pack_hash", "model_hash", "lexshield_policy_hash"], "snapshot"
    )
    if not _is_pos_int(o["epoch"]):
        raise ClosedError("INVALID_REQUEST", "epoch")
    if not (is_hash(o["config_hash"]) and is_hash(o["pack_hash"]) and is_hash(o["lexshield_policy_hash"])):
        raise ClosedError("INVALID_REQUEST", "snapshot hash")
    if o["model_hash"] is not None and not is_hash(o["model_hash"]):
        raise ClosedError("INVALID_REQUEST", "model_hash")
    return o


def validate_span(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "span")
    o = v
    check_exact_keys(o, ["block", "start", "end"], "span")
    if not _is_nonneg_int(o["block"]):
        raise ClosedError("INVALID_REQUEST", "span.block")
    if not (_is_nonneg_int(o["start"]) and _is_nonneg_int(o["end"])):
        raise ClosedError("INVALID_REQUEST", "span offset")
    if o["end"] <= o["start"] or o["end"] > 32768:
        raise ClosedError("INVALID_REQUEST", "span range")
    return o


def validate_findings(v):
    if not isinstance(v, list) or len(v) > 64:
        raise ClosedError("INVALID_REQUEST", "findings")
    out = []
    for f in v:
        if not is_obj(f):
            raise ClosedError("INVALID_REQUEST", "finding")
        check_exact_keys(f, ["rule_id", "class", "span"], "finding")
        if not isinstance(f["rule_id"], str) or not _TAG_RE.match(f["rule_id"]):
            raise ClosedError("INVALID_REQUEST", "rule_id")
        if f["class"] not in CLASSES:
            raise ClosedError("INVALID_REQUEST", "class")
        span = None if f["span"] is None else validate_span(f["span"])
        out.append({"rule_id": f["rule_id"], "class": f["class"], "span": span})
    return out


def validate_policy_response(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "policy response")
    o = v
    check_exact_keys(o, ["v", "policy_hash", "disposition", "reason"], "policy response")
    if o["v"] != 1:
        raise ClosedError("INVALID_REQUEST", "v")
    if not is_hash(o["policy_hash"]):
        raise ClosedError("INVALID_REQUEST", "policy_hash")
    if o["disposition"] not in ("allow", "block"):
        raise ClosedError("INVALID_REQUEST", "disposition")
    if o["reason"] not in ("POLICY_ALLOW", "BLOCK_CLASS", "HARD_DENY"):
        raise ClosedError("INVALID_REQUEST", "policy reason")
    return o


def validate_decision(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "decision")
    o = v
    check_exact_keys(
        o,
        [
            "decision_id", "result_id", "input_hash", "snapshot", "policy_result", "verdict",
            "reason", "findings", "replacements", "output_hash", "quarantine_id",
        ],
        "decision",
    )
    require_id("lsdec", o["decision_id"], "decision_id")
    require_id("lsres", o["result_id"], "result_id")
    if not (is_hash(o["input_hash"]) and is_hash(o["output_hash"])):
        raise ClosedError("INVALID_REQUEST", "decision hash")
    snapshot = validate_snapshot(o["snapshot"])
    policy_result = None if o["policy_result"] is None else validate_policy_response(o["policy_result"])
    if o["verdict"] not in VERDICTS:
        raise ClosedError("INVALID_REQUEST", "verdict")
    if o["reason"] not in REASONS:
        raise ClosedError("INVALID_REQUEST", "reason")
    findings = validate_findings(o["findings"])
    if not isinstance(o["replacements"], list) or len(o["replacements"]) > 64:
        raise ClosedError("INVALID_REQUEST", "replacements")
    replacements = [validate_span(x) for x in o["replacements"]]
    if o["quarantine_id"] is not None and not is_valid_id("lsq", o["quarantine_id"]):
        raise ClosedError("INVALID_REQUEST", "quarantine_id")
    return {
        "decision_id": o["decision_id"],
        "result_id": o["result_id"],
        "input_hash": o["input_hash"],
        "snapshot": snapshot,
        "policy_result": policy_result,
        "verdict": o["verdict"],
        "reason": o["reason"],
        "findings": findings,
        "replacements": replacements,
        "output_hash": o["output_hash"],
        "quarantine_id": o["quarantine_id"],
    }


def validate_receipt_body(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "receipt body")
    o = v
    check_exact_keys(
        o,
        ["v", "receipt_id", "tenant_id", "gateway_id", "seq", "recorded_at_ms", "prev_hash", "decision"],
        "receipt body",
    )
    if o["v"] != 1:
        raise ClosedError("INVALID_REQUEST", "v")
    require_id("lsrcp", o["receipt_id"], "receipt_id")
    require_id("lsten", o["tenant_id"], "tenant_id")
    require_id("lsgw", o["gateway_id"], "gateway_id")
    if not _is_pos_int(o["seq"]):
        raise ClosedError("INVALID_REQUEST", "seq")
    if not _is_nonneg_int(o["recorded_at_ms"]):
        raise ClosedError("INVALID_REQUEST", "recorded_at_ms")
    if not is_hash(o["prev_hash"]):
        raise ClosedError("INVALID_REQUEST", "prev_hash")
    decision = validate_decision(o["decision"])
    return {
        "v": 1,
        "receipt_id": o["receipt_id"],
        "tenant_id": o["tenant_id"],
        "gateway_id": o["gateway_id"],
        "seq": o["seq"],
        "recorded_at_ms": o["recorded_at_ms"],
        "prev_hash": o["prev_hash"],
        "decision": decision,
    }


def validate_signed_receipt(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "receipt")
    o = v
    check_exact_keys(o, ["body", "hash", "key_id", "signature"], "receipt")
    body = validate_receipt_body(o["body"])
    if not is_hash(o["hash"]):
        raise ClosedError("INVALID_REQUEST", "hash")
    require_id("lskey", o["key_id"], "key_id")
    if not is_b64u(o["signature"], 64):
        raise ClosedError("INVALID_REQUEST", "signature")
    return {"body": body, "hash": o["hash"], "key_id": o["key_id"], "signature": o["signature"]}


def validate_envelope(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "envelope")
    o = v
    check_exact_keys(
        o,
        ["type", "result_id", "decision_id", "receipt_id", "trust", "disposition",
         "provenance", "notice", "data"],
        "envelope",
    )
    if o["type"] != "lexsieve.tool-data.v1":
        raise ClosedError("INVALID_REQUEST", "type")
    require_id("lsres", o["result_id"], "result_id")
    require_id("lsdec", o["decision_id"], "decision_id")
    require_id("lsrcp", o["receipt_id"], "receipt_id")
    if o["trust"] != "untrusted":
        raise ClosedError("INVALID_REQUEST", "trust")
    if o["disposition"] not in VERDICTS:
        raise ClosedError("INVALID_REQUEST", "disposition")
    pv = o["provenance"]
    if not is_obj(pv):
        raise ClosedError("INVALID_REQUEST", "provenance")
    check_exact_keys(pv, ["tool", "adapter", "content_sha256"], "provenance")
    if not isinstance(pv["tool"], str) or not _TOOL_RE.match(pv["tool"]):
        raise ClosedError("INVALID_REQUEST", "provenance.tool")
    if pv["adapter"] not in ("native", "mcp", "openai"):
        raise ClosedError("INVALID_REQUEST", "provenance.adapter")
    if not is_hash(pv["content_sha256"]):
        raise ClosedError("INVALID_REQUEST", "content_sha256")
    notice = o["notice"]
    if notice is not None and notice not in (
        "Suspect spans removed.",
        "Tool result withheld by LexSieve.",
    ):
        raise ClosedError("INVALID_REQUEST", "notice")
    dv = o["data"]
    if not isinstance(dv, list) or len(dv) > 8:
        raise ClosedError("INVALID_REQUEST", "data")
    for i, b in enumerate(dv):
        if not is_obj(b):
            raise ClosedError("INVALID_REQUEST", "data block")
        check_exact_keys(b, ["index", "text"], "data block")
        if b["index"] != i:
            raise ClosedError("INVALID_REQUEST", "data index")
        if not isinstance(b["text"], str) or len(b["text"].encode("utf-8")) > 32768:
            raise ClosedError("INVALID_REQUEST", "data text")
    return o


def validate_pack_body(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "pack body")
    o = v
    check_exact_keys(
        o,
        ["v", "pack_id", "serial", "core_min", "builtin_revision", "created_at_ms",
         "expires_at_ms", "rules", "model"],
        "pack body",
    )
    if o["v"] != 1:
        raise ClosedError("INVALID_REQUEST", "v")
    require_id("lspack", o["pack_id"], "pack_id")
    if not _is_pos_int(o["serial"]):
        raise ClosedError("INVALID_REQUEST", "serial")
    if not isinstance(o["core_min"], str) or not _SEMVER_RE.match(o["core_min"]):
        raise ClosedError("INVALID_REQUEST", "core_min")
    if o["builtin_revision"] != "builtin-1":
        raise ClosedError("INVALID_REQUEST", "builtin_revision")
    if not (_is_nonneg_int(o["created_at_ms"]) and _is_nonneg_int(o["expires_at_ms"])):
        raise ClosedError("INVALID_REQUEST", "times")
    if o["expires_at_ms"] <= o["created_at_ms"]:
        raise ClosedError("INVALID_REQUEST", "expiry before creation")
    if o["expires_at_ms"] - o["created_at_ms"] > 90 * 86400000:
        raise ClosedError("INVALID_REQUEST", "expiry window")
    model = None if o["model"] is None else validate_model_artifact(o["model"])
    return {
        "v": 1,
        "pack_id": o["pack_id"],
        "serial": o["serial"],
        "core_min": o["core_min"],
        "builtin_revision": "builtin-1",
        "created_at_ms": o["created_at_ms"],
        "expires_at_ms": o["expires_at_ms"],
        "rules": o["rules"],
        "model": model,
    }


def validate_signed_pack(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "pack")
    o = v
    check_exact_keys(o, ["body", "hash", "key_id", "signature"], "pack")
    body = validate_pack_body(o["body"])
    if not is_hash(o["hash"]):
        raise ClosedError("INVALID_REQUEST", "pack hash")
    require_id("lskey", o["key_id"], "key_id")
    if not is_b64u(o["signature"], 64):
        raise ClosedError("INVALID_REQUEST", "signature")
    return {"body": body, "hash": o["hash"], "key_id": o["key_id"], "signature": o["signature"]}


def validate_trust_config(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "trust")
    o = v
    check_exact_keys(o, ["v", "keys"], "trust")
    if o["v"] != 1:
        raise ClosedError("INVALID_REQUEST", "v")
    if not isinstance(o["keys"], list) or not (1 <= len(o["keys"]) <= 64):
        raise ClosedError("INVALID_REQUEST", "trust keys")
    seen = set()
    keys = []
    for k in o["keys"]:
        if not is_obj(k):
            raise ClosedError("INVALID_REQUEST", "trust key")
        check_exact_keys(k, ["key_id", "public_key", "purpose", "revoked"], "trust key")
        require_id("lskey", k["key_id"], "key_id")
        if not is_b64u(k["public_key"], 32):
            raise ClosedError("INVALID_REQUEST", "public_key")
        if k["purpose"] not in ("pack", "receipt"):
            raise ClosedError("INVALID_REQUEST", "purpose")
        if not isinstance(k["revoked"], bool):
            raise ClosedError("INVALID_REQUEST", "revoked")
        if k["key_id"] in seen:
            raise ClosedError("INVALID_REQUEST", "duplicate key_id")
        seen.add(k["key_id"])
        keys.append(k)
    return {"v": 1, "keys": keys}


def validate_config(v):
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "config")
    o = v
    check_exact_keys(
        o,
        [
            "v", "tenant_id", "gateway_id", "mode", "pack_file", "trust_file", "signer_key_id",
            "signer_seed_env", "receipt_sink", "lexshield", "telemetry", "max_inflight",
            "retention_days",
        ],
        "config",
    )
    if o["v"] != 1:
        raise ClosedError("INVALID_REQUEST", "v")
    require_id("lsten", o["tenant_id"], "tenant_id")
    require_id("lsgw", o["gateway_id"], "gateway_id")
    if o["mode"] not in ("required", "rules_only"):
        raise ClosedError("INVALID_REQUEST", "mode")
    if (
        not isinstance(o["pack_file"], str)
        or not isinstance(o["trust_file"], str)
        or not o["pack_file"]
        or not o["trust_file"]
    ):
        raise ClosedError("INVALID_REQUEST", "file path")
    require_id("lskey", o["signer_key_id"], "signer_key_id")
    if not isinstance(o["signer_seed_env"], str) or not _ENV_RE.match(o["signer_seed_env"]):
        raise ClosedError("INVALID_REQUEST", "signer_seed_env")
    rs = o["receipt_sink"]
    if not is_obj(rs):
        raise ClosedError("INVALID_REQUEST", "receipt_sink")
    if rs.get("kind") == "sqlite":
        check_exact_keys(rs, ["kind", "path"], "receipt_sink")
        if not isinstance(rs["path"], str) or not rs["path"]:
            raise ClosedError("INVALID_REQUEST", "sink path")
        receipt_sink = {"kind": "sqlite", "path": rs["path"]}
    elif rs.get("kind") == "durable_object":
        check_exact_keys(rs, ["kind", "binding"], "receipt_sink")
        if not isinstance(rs["binding"], str) or not rs["binding"]:
            raise ClosedError("INVALID_REQUEST", "sink binding")
        receipt_sink = {"kind": "durable_object", "binding": rs["binding"]}
    else:
        raise ClosedError("INVALID_REQUEST", "sink kind")
    ls = o["lexshield"]
    if not is_obj(ls):
        raise ClosedError("INVALID_REQUEST", "lexshield")
    if ls.get("kind") == "static":
        check_exact_keys(ls, ["kind"], "lexshield")
        lexshield = {"kind": "static"}
    elif ls.get("kind") == "axion":
        check_exact_keys(ls, ["kind", "binding", "policy_hash"], "lexshield")
        if not isinstance(ls["binding"], str) or not ls["binding"]:
            raise ClosedError("INVALID_REQUEST", "binding")
        if not is_hash(ls["policy_hash"]):
            raise ClosedError("INVALID_REQUEST", "policy_hash")
        lexshield = {"kind": "axion", "binding": ls["binding"], "policy_hash": ls["policy_hash"]}
    else:
        raise ClosedError("INVALID_REQUEST", "lexshield kind")
    tel = o["telemetry"]
    if not is_obj(tel):
        raise ClosedError("INVALID_REQUEST", "telemetry")
    check_exact_keys(tel, ["enabled", "origin", "token_env"], "telemetry")
    if not isinstance(tel["enabled"], bool):
        raise ClosedError("INVALID_REQUEST", "telemetry.enabled")
    if tel["enabled"]:
        if not isinstance(tel["origin"], str) or not _ORIGIN_RE.match(tel["origin"]):
            raise ClosedError("INVALID_REQUEST", "telemetry.origin")
        if not isinstance(tel["token_env"], str) or not _ENV_RE.match(tel["token_env"]):
            raise ClosedError("INVALID_REQUEST", "telemetry.token_env")
        telemetry = {"enabled": True, "origin": tel["origin"], "token_env": tel["token_env"]}
    else:
        if tel["origin"] is not None or tel["token_env"] is not None:
            raise ClosedError("INVALID_REQUEST", "telemetry disabled requires nulls")
        telemetry = {"enabled": False, "origin": None, "token_env": None}
    if not _is_pos_int(o["max_inflight"]) or o["max_inflight"] > 64:
        raise ClosedError("INVALID_REQUEST", "max_inflight")
    if not _is_pos_int(o["retention_days"]) or o["retention_days"] > 365:
        raise ClosedError("INVALID_REQUEST", "retention_days")
    return {
        "v": 1,
        "tenant_id": o["tenant_id"],
        "gateway_id": o["gateway_id"],
        "mode": o["mode"],
        "pack_file": o["pack_file"],
        "trust_file": o["trust_file"],
        "signer_key_id": o["signer_key_id"],
        "signer_seed_env": o["signer_seed_env"],
        "receipt_sink": receipt_sink,
        "lexshield": lexshield,
        "telemetry": telemetry,
        "max_inflight": o["max_inflight"],
        "retention_days": o["retention_days"],
    }
