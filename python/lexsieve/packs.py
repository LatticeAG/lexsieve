"""Pack verification and activation (spec 8, 9.2). Pack verification does
not mean policy activation; activation is a separate local atomic operation
enforcing persisted monotonic serials.
"""

from .crypto import b64u_decode, sha256_hex
from .errors import ClosedError
from .jcs import jcs, jcs_bytes
from .model import model_hash
from .receipts import pack_hash, verify_pack_signature
from .rules import compile_pack_rules
from .schema import validate_pack_body, validate_signed_pack

CORE_VERSION = "1.0.0"


def compare_semver(a, b):
    pa = [int(x) for x in a.split(".")]
    pb = [int(x) for x in b.split(".")]
    for i in range(3):
        if pa[i] != pb[i]:
            return -1 if pa[i] < pb[i] else 1
    return 0


def verify_pack(pack, trust, now_ms):
    """verifyPack: validates schema, hash, signature/trust, core
    compatibility, and validity window
    (created_at_ms <= now_ms < expires_at_ms). Failure returns
    {"valid": False, "reason": ...}; never raises for well-formed JSON."""
    try:
        body = validate_pack_body(pack["body"])
        compile_pack_rules(pack["body"]["rules"])
        if len(jcs(pack["body"]).encode("utf-8")) > 262144:
            return {"valid": False, "reason": "SCHEMA"}
        if compare_semver(body["core_min"], CORE_VERSION) > 0:
            return {"valid": False, "reason": "SCHEMA"}
    except Exception:
        return {"valid": False, "reason": "SCHEMA"}
    if pack_hash(pack["body"]) != pack["hash"]:
        return {"valid": False, "reason": "HASH"}
    key = next((k for k in trust["keys"] if k["key_id"] == pack["key_id"]), None)
    if not key or key["purpose"] != "pack":
        return {"valid": False, "reason": "SCHEMA"}
    if key["revoked"]:
        return {"valid": False, "reason": "SIGNATURE"}
    if not verify_pack_signature(pack, b64u_decode(key["public_key"])):
        return {"valid": False, "reason": "SIGNATURE"}
    if not (body["created_at_ms"] <= now_ms < body["expires_at_ms"]):
        return {"valid": False, "reason": "SCHEMA"}
    return {"valid": True, "reason": "VALID"}


def verify_pack_untimed(pack, trust):
    """Structural pack verification without the time window — used by reload
    and check-config where the caller reports expiry separately."""
    try:
        validate_pack_body(pack["body"])
        compile_pack_rules(pack["body"]["rules"])
        if len(jcs(pack["body"]).encode("utf-8")) > 262144:
            return {"valid": False, "reason": "SCHEMA"}
        if compare_semver(pack["body"]["core_min"], CORE_VERSION) > 0:
            return {"valid": False, "reason": "SCHEMA"}
    except Exception:
        return {"valid": False, "reason": "SCHEMA"}
    if pack_hash(pack["body"]) != pack["hash"]:
        return {"valid": False, "reason": "HASH"}
    key = next((k for k in trust["keys"] if k["key_id"] == pack["key_id"]), None)
    if not key or key["purpose"] != "pack":
        return {"valid": False, "reason": "SCHEMA"}
    if key["revoked"]:
        return {"valid": False, "reason": "SIGNATURE"}
    if not verify_pack_signature(pack, b64u_decode(key["public_key"])):
        return {"valid": False, "reason": "SIGNATURE"}
    return {"valid": True, "reason": "VALID"}


def activate_pack(sink, config, trust, pack, now_ms, config_hash, lexshield_policy_hash):
    """Atomic activation under the monotonic-serial rule (spec 8, 9.2).
    Raises ClosedError CONFLICT on downgrade/equivocation; NOT_READY on
    expiry or untrusted artifact. Returns the new epoch."""
    v = verify_pack(pack, trust, now_ms)
    if not v["valid"]:
        raise ClosedError("NOT_READY", f"pack activation: {v['reason']}")
    tenant = config["tenant_id"]
    max_serial = sink.get_max_pack_serial(tenant, pack["body"]["pack_id"])
    stored = sink.get_pack(tenant, pack["body"]["pack_id"], pack["body"]["serial"])
    if stored and stored["hash"] != pack["hash"]:
        raise ClosedError("CONFLICT", "pack equivocation")
    if max_serial is not None and pack["body"]["serial"] < max_serial:
        raise ClosedError("CONFLICT", "pack downgrade")
    active = sink.get_active_snapshot(tenant, config["gateway_id"])
    if (
        active
        and active["pack_id"] == pack["body"]["pack_id"]
        and active["pack_hash"] == pack["hash"]
    ):
        return active["epoch"]  # idempotent re-activation
    sink.put_pack(tenant, pack)
    epoch = (active["epoch"] if active else 0) + 1
    snapshot = {
        "epoch": epoch,
        "config_hash": config_hash,
        "pack_hash": pack["hash"],
        "model_hash": (
            model_hash(_validate_model_for_activation(pack))
            if config["mode"] == "required"
            else None
        ),
        "lexshield_policy_hash": lexshield_policy_hash,
    }
    sink.set_active_snapshot(tenant, config["gateway_id"], {
        "epoch": epoch,
        "snapshot": snapshot,
        "pack_id": pack["body"]["pack_id"],
        "pack_serial": pack["body"]["serial"],
        "pack_expires_at_ms": pack["body"]["expires_at_ms"],
        "pack_hash": pack["hash"],
    })
    return epoch


def _validate_model_for_activation(pack):
    if not pack["body"]["model"]:
        raise ClosedError("NOT_READY", "required mode needs a model")
    return pack["body"]["model"]


def config_hash_of(config):
    return sha256_hex(jcs_bytes(config))
