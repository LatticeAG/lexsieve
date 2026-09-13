"""Section 10.1/9.3: local telemetry spool plus the hosted ingest validation
logic (tenant-DO semantics, spec 10.2/11). The hosted HTTP transport itself
is the paid surface — see hosted.py stubs — but the batch validation and
aggregate counting are pure library logic exercised by conformance vectors.
"""

from .crypto import b64u_decode, sha256_hex
from .jcs import jcs
from .receipts import receipt_hash, verify_receipt_with_key
from .schema import validate_signed_receipt
from .ids import is_valid_id

_DURATION_BUCKETS = ("lt25", "25to99", "100to179", "ge180")
_ZERO_HASH = "0" * 64


def _err(code, retryable=False):
    return {
        "v": 1,
        "error": {"code": code, "retryable": retryable, "request_id": "lsreq_000000000000000000000"},
    }


class TenantTelemetryStore:
    """In-memory tenant-DO equivalent for hosted telemetry ingest. Validates
    the complete batch (auth, chain contiguity, signatures, profile match)
    before one atomic ingest."""

    def __init__(self, hosted):
        self.hosted = hosted
        self.batches = {}       # batch_id -> sha256 of canonical request body
        self.aggregates = {}    # day|gateway|pack_hash|mode|verdict -> count
        self.checkpoints = {}   # gateway_id -> {seq, hash}

    def _grant_for(self, token_hash):
        return next((g for g in self.hosted["grants"] if g["token_hash"] == token_hash), None)

    # role check + tenant binding; reader cannot write, writer cannot read.
    def ingest(self, req, presented_token):
        token_hash = sha256_hex(presented_token)
        grant = self._grant_for(token_hash)
        if not grant:
            return {"status": 401, "body": _err("UNAUTHENTICATED"), "accepted": 0}
        if grant["role"] != "telemetry_writer":
            return {"status": 403, "body": _err("FORBIDDEN"), "accepted": 0}
        if (
            not is_valid_id("lsbatch", req.get("batch_id"))
            or not isinstance(req.get("events"), list)
            or not (1 <= len(req["events"]) <= 64)
        ):
            return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
        # validate all receipts: one gateway registered to the tenant,
        # contiguous seq order, verified under the gateway's provisioned
        # receipt keys.
        gateway_id = None
        gw = None
        parsed = []
        for ev in req["events"]:
            try:
                receipt = validate_signed_receipt(ev["receipt"])
            except Exception:
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
            if receipt["body"]["tenant_id"] != grant["tenant_id"]:
                return {"status": 403, "body": _err("FORBIDDEN"), "accepted": 0}
            if gateway_id is None:
                gateway_id = receipt["body"]["gateway_id"]
                gw = next(
                    (
                        g
                        for g in self.hosted["gateways"]
                        if g["tenant_id"] == grant["tenant_id"] and g["gateway_id"] == gateway_id
                    ),
                    None,
                )
                if not gw:
                    return {"status": 403, "body": _err("FORBIDDEN"), "accepted": 0}
            elif receipt["body"]["gateway_id"] != gateway_id:
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
            gw_keys = gw["receipt_key_ids"]
            key_entry = next(
                (
                    k
                    for k in self.hosted["trust"]["keys"]
                    if k["key_id"] == receipt["key_id"] and k["key_id"] in gw_keys
                ),
                None,
            )
            if not key_entry or key_entry["purpose"] != "receipt" or key_entry["revoked"]:
                return {"status": 400, "body": _err("BAD_SIGNATURE"), "accepted": 0}
            # full hash+signature validation (link checked against
            # checkpoint below)
            if receipt_hash(receipt["body"]) != receipt["hash"]:
                return {"status": 400, "body": _err("BAD_SIGNATURE"), "accepted": 0}
            sig = verify_receipt_with_key(
                receipt,
                b64u_decode(key_entry["public_key"]),
                receipt["body"]["prev_hash"],
                receipt["body"]["seq"],
            )
            if not sig["valid"]:
                return {"status": 400, "body": _err("BAD_SIGNATURE"), "accepted": 0}
            # profile match
            profile = next(
                (
                    p
                    for p in gw["profiles"]
                    if p["config_hash"] == receipt["body"]["decision"]["snapshot"]["config_hash"]
                ),
                None,
            )
            if not profile or ev.get("mode") != profile["mode"]:
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
            if ev["mode"] not in ("required", "rules_only"):
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
            if ev.get("duration_bucket") not in _DURATION_BUCKETS:
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
            parsed.append(
                {"receipt": receipt, "mode": ev["mode"], "bucket": ev["duration_bucket"]}
            )
        # internal contiguity
        for i in range(1, len(parsed)):
            if parsed[i]["receipt"]["body"]["seq"] != parsed[i - 1]["receipt"]["body"]["seq"] + 1:
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
            if parsed[i]["receipt"]["body"]["prev_hash"] != parsed[i - 1]["receipt"]["hash"]:
                return {"status": 400, "body": _err("INVALID_REQUEST"), "accepted": 0}
        # dedupe identity: batch_id + sha256 of canonical body
        canon = jcs(req)
        batch_hash = sha256_hex(canon)
        existing = self.batches.get(req["batch_id"])
        if existing is not None:
            if existing == batch_hash:
                head = self.checkpoints.get(gateway_id)
                return {
                    "status": 200,
                    "body": {
                        "v": 1,
                        "batch_id": req["batch_id"],
                        "accepted": 0,
                        "duplicate": True,
                        "head_seq": head["seq"] if head else 0,
                        "head_hash": head["hash"] if head else _ZERO_HASH,
                    },
                    "accepted": 0,
                }
            return {"status": 409, "body": _err("CONFLICT"), "accepted": 0}
        # chain head check
        head = self.checkpoints.get(gateway_id)
        if head is None:
            cp = gw["checkpoint"]
            head = (
                {"seq": cp["body"]["seq"], "hash": cp["hash"]}
                if cp
                else {"seq": 0, "hash": _ZERO_HASH}
            )
        first = parsed[0]["receipt"]
        # already-known identical prefix is allowed; count only the new suffix
        start_idx = 0
        if first["body"]["seq"] <= head["seq"]:
            while start_idx < len(parsed) and parsed[start_idx]["receipt"]["body"]["seq"] <= head["seq"]:
                start_idx += 1
        if start_idx >= len(parsed):
            return {
                "status": 200,
                "body": {
                    "v": 1,
                    "batch_id": req["batch_id"],
                    "accepted": 0,
                    "duplicate": False,
                    "head_seq": head["seq"],
                    "head_hash": head["hash"],
                },
                "accepted": 0,
            }
        first_new = parsed[start_idx]["receipt"]
        if (
            first_new["body"]["seq"] != head["seq"] + 1
            or first_new["body"]["prev_hash"] != head["hash"]
        ):
            return {"status": 409, "body": _err("CHAIN_GAP", True), "accepted": 0}
        # future-timestamp rejection is applied by the HTTP layer using the
        # deployment clock; this store is clock-free.
        # atomic ingest
        for i in range(start_idx, len(parsed)):
            receipt, mode = parsed[i]["receipt"], parsed[i]["mode"]
            day = receipt["body"]["recorded_at_ms"] // 86400000
            key = (
                f"{day}|{receipt['body']['gateway_id']}|"
                f"{receipt['body']['decision']['snapshot']['pack_hash']}|"
                f"{mode}|{receipt['body']['decision']['verdict']}"
            )
            self.aggregates[key] = self.aggregates.get(key, 0) + 1
            self.checkpoints[receipt["body"]["gateway_id"]] = {
                "seq": receipt["body"]["seq"],
                "hash": receipt["hash"],
            }
        self.batches[req["batch_id"]] = batch_hash
        new_head = self.checkpoints[gateway_id]
        return {
            "status": 202,
            "body": {
                "v": 1,
                "batch_id": req["batch_id"],
                "accepted": len(parsed) - start_idx,
                "duplicate": False,
                "head_seq": new_head["seq"],
                "head_hash": new_head["hash"],
            },
            "accepted": len(parsed) - start_idx,
        }

    def aggregate_count(self, gateway_id, pack_hash_, mode, verdict):
        n = 0
        for k, v in self.aggregates.items():
            parts = k.split("|")
            if (
                parts[1] == gateway_id
                and parts[2] == pack_hash_
                and parts[3] == mode
                and parts[4] == verdict
            ):
                n += v
        return n

    def head_seq(self, gateway_id):
        h = self.checkpoints.get(gateway_id)
        return h["seq"] if h else 0


# --- Local spool helpers -----------------------------------------------------

SPOOL_TTL_MS = 24 * 3600 * 1000
SPOOL_MAX_BYTES = 16 * 1024 * 1024
SPOOL_MAX_BATCHES = 4096
