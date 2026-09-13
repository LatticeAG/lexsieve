"""Section 7 verification RPCs: verify_receipt, verify_pack, replay.
Verification checks schema, body hash, signature, then chain link in that
order. Pure functions — no key fetch, no network, no live policy service.
"""

from .crypto import b64u_decode, sha256_hex
from .errors import ClosedError
from .jcs import jcs
from .packs import verify_pack as verify_pack_core
from .receipts import verify_receipt_with_key
from .rules import dedup_sort_findings
from .engine import apply_replacements
from .schema import (
    validate_decision,
    validate_envelope,
    validate_screen_request,
    validate_signed_pack,
    validate_signed_receipt,
    validate_trust_config,
)


def verify_receipt(req):
    try:
        receipt = validate_signed_receipt(req["receipt"])
        pub = b64u_decode(req["public_key"])
        if len(pub) != 32:
            return {"v": 1, "valid": False, "reason": "SCHEMA"}
    except Exception:
        return {"v": 1, "valid": False, "reason": "SCHEMA"}
    r = verify_receipt_with_key(receipt, pub, req["expected_prev_hash"], req["expected_seq"])
    return {"v": 1, "valid": r["valid"], "reason": r["reason"]}


def verify_receipt_trust(receipt, trust, expected_prev_hash, expected_seq):
    """Receipt verification under a trust file: the key must exist with
    purpose "receipt" and be unrevoked (current trust). Historical
    verification passes an explicitly supplied historical trust config."""
    try:
        r = validate_signed_receipt(receipt)
    except Exception:
        return {"v": 1, "valid": False, "reason": "SCHEMA"}
    key = next((k for k in trust["keys"] if k["key_id"] == r["key_id"]), None)
    if not key or key["purpose"] != "receipt":
        return {"v": 1, "valid": False, "reason": "SCHEMA"}
    if key["revoked"]:
        return {"v": 1, "valid": False, "reason": "SIGNATURE"}
    res = verify_receipt_with_key(
        r, b64u_decode(key["public_key"]), expected_prev_hash, expected_seq
    )
    return {"v": 1, "valid": res["valid"], "reason": res["reason"]}


def verify_pack(req):
    try:
        pack = validate_signed_pack(req["pack"])
        validate_trust_config(req["trust"])
    except Exception:
        return {"v": 1, "valid": False, "reason": "SCHEMA"}
    r = verify_pack_core(pack, req["trust"], req["now_ms"])
    return {"v": 1, "valid": r["valid"], "reason": r["reason"]}


_DIFF_ORDER = ["input", "policy", "findings", "transform", "output"]


def replay(engine, req):
    """replay(ReplayRequest) -> ReplayResponse. Requires the recorded
    artifacts locally (pack by hash; model inside that pack); uses the
    recorded policy_result — never invokes a live policy service, allocates
    no IDs, appends no receipt, delivers nothing."""
    request = validate_screen_request(req["request"])
    recorded_decision = validate_decision(req["recorded"]["decision"])
    recorded_envelope = validate_envelope(req["recorded"]["envelope"])
    recorded_receipt = validate_signed_receipt(req["recorded"]["receipt"])

    differences = set()

    input_hash = sha256_hex(jcs(request["candidate"]))
    if input_hash != recorded_decision["input_hash"]:
        differences.add("input")

    snap = recorded_decision["snapshot"]
    stored_pack = engine.deps["sink"].get_pack_by_hash(
        engine.config["tenant_id"], snap["pack_hash"]
    )
    if not stored_pack:
        raise ClosedError("NOT_FOUND", "recorded pack artifact not archived locally")
    if snap["model_hash"] is not None:
        m = stored_pack["pack"]["body"]["model"]
        if not m or sha256_hex(jcs(m)) != snap["model_hash"]:
            raise ClosedError("NOT_FOUND", "recorded model artifact not archived locally")

    # Recompute the deterministic pipeline under the recorded snapshot; the
    # recorded policy_result is used verbatim (never a live callback).
    ctx = engine.bare_ctx(request, snap)
    prev_artifact = engine.artifact
    prev_hash = engine.artifact_hash
    prev_mode = engine.mode_override
    try:
        engine.artifact = None if snap["model_hash"] is None else stored_pack["pack"]["body"]["model"]
        engine.artifact_hash = snap["model_hash"]
        engine.mode_override = "rules_only" if snap["model_hash"] is None else "required"
        engine.run_local(ctx)
        ctx.policy_result = recorded_decision["policy_result"]
    finally:
        engine.artifact = prev_artifact
        engine.artifact_hash = prev_hash
        engine.mode_override = prev_mode

    findings_jcs = jcs(dedup_sort_findings(ctx.findings)[:64])
    if findings_jcs != jcs(recorded_decision["findings"]):
        differences.add("findings")
    replacements_sorted = sorted(ctx.replacements, key=lambda s: (s["block"], s["start"], s["end"]))
    if jcs(replacements_sorted) != jcs(recorded_decision["replacements"]):
        differences.add("transform")
    if jcs(recorded_decision["policy_result"]) != jcs(ctx.policy_result):
        differences.add("policy")
    # For infrastructure holds, replay treats the signed failure reason as
    # an observation and validates a closed output: verdict must be hold and
    # the envelope must be empty.
    env = _rebuild_envelope(
        recorded_decision, request, recorded_receipt, recorded_envelope["notice"]
    )
    if sha256_hex(jcs(env)) != recorded_decision["output_hash"]:
        differences.add("output")
    return {
        "v": 1,
        "equal": len(differences) == 0,
        "differences": [d for d in _DIFF_ORDER if d in differences],
    }


def _rebuild_envelope(decision, request, receipt, notice):
    data = []
    if decision["verdict"] == "pass":
        data = request["candidate"]["blocks"]
    elif decision["verdict"] == "strip":
        data = apply_replacements(request["candidate"]["blocks"], decision["replacements"])[0]
    return {
        "type": "lexsieve.tool-data.v1",
        "result_id": request["candidate"]["result_id"],
        "decision_id": decision["decision_id"],
        "receipt_id": receipt["body"]["receipt_id"],
        "trust": "untrusted",
        "disposition": decision["verdict"],
        "provenance": {
            "tool": request["candidate"]["binding"]["tool"],
            "adapter": request["candidate"]["binding"]["adapter"],
            "content_sha256": sha256_hex(jcs(request["candidate"]["blocks"])),
        },
        "notice": notice,
        "data": data,
    }
