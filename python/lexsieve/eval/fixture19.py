"""Section 19 exact fixture objects: I, J, H, U, B, B64, S functions and the
named constants seed, pub, Z, H0, M0, PB0, PH0, P0, T0, C0, Q0, E0, D0, R0,
S0. All values are computed by the real implementation; the printed golden
anchors in the spec (input_hash, pack_hash, receipt hash, signature) are
asserted by the conformance suite.
"""

from ..crypto import (
    b64u_encode,
    ed25519_public_from_seed,
    ed25519_sign,
    hex_decode,
    sha256_hex,
)
from ..jcs import jcs
from ..lexshield import STATIC_POLICY_HASH
from ..model import model_hash
from ..receipts import pack_hash, sign_pack, sign_receipt

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUB_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
seed = hex_decode(SEED_HEX)
pub = ed25519_public_from_seed(seed)
Z = "0" * 64
H0 = STATIC_POLICY_HASH


def I(prefix, c):
    """I(prefix,c): prefix + "_" + 21 repetitions of c."""
    return f"{prefix}_{c * 21}"


J = jcs
H = sha256_hex
U = lambda s: s.encode("utf-8")
B = hex_decode
B64 = b64u_encode
S = ed25519_sign


class LetterAllocator:
    """Per-prefix letter allocator: first ID of each prefix gets 'A' x21,
    then B..."""

    def __init__(self):
        self.counts = {}

    def next(self, prefix):
        n = self.counts.get(prefix, 0)
        self.counts[prefix] = n + 1
        return I(prefix, chr(0x41 + n))


def letter_allocator():
    return LetterAllocator()


M0 = {
    "format": "lexsieve.linear.v1",
    "unicode": "15.1.0",
    "tokenizer": "word-ngram-1-3-v1",
    "classes": ["override", "exfiltration", "tool_directive"],
    "bias": [-500, -500, -500],
    "threshold": 0,
    "weights": [
        {"feature": "credential", "values": [0, 1000, 0]},
        {"feature": "forget", "values": [1000, 0, 0]},
        {"feature": "terminal", "values": [0, 0, 1000]},
    ],
}

PB0 = {
    "v": 1,
    "pack_id": I("lspack", "A"),
    "serial": 1,
    "core_min": "1.0.0",
    "builtin_revision": "builtin-1",
    "created_at_ms": 0,
    "expires_at_ms": 86400000,
    "rules": [],
    "model": M0,
}
PH0 = pack_hash(PB0)
_sig = sign_pack(PB0, seed)
P0 = {"body": PB0, "hash": _sig["hash"], "key_id": I("lskey", "A"), "signature": _sig["signature"]}

T0 = {
    "v": 1,
    "keys": [
        {"key_id": I("lskey", "A"), "public_key": B64(pub), "purpose": "pack", "revoked": False},
        {"key_id": I("lskey", "B"), "public_key": B64(pub), "purpose": "receipt", "revoked": False},
    ],
}

C0 = {
    "v": 1,
    "tenant_id": I("lsten", "A"),
    "gateway_id": I("lsgw", "A"),
    "mode": "rules_only",
    "pack_file": "./packs/active.json",
    "trust_file": "./trust.json",
    "signer_key_id": I("lskey", "B"),
    "signer_seed_env": "LEXSIEVE_RECEIPT_SEED",
    "receipt_sink": {"kind": "sqlite", "path": "./state/lexsieve.sqlite"},
    "lexshield": {"kind": "static"},
    "telemetry": {"enabled": False, "origin": None, "token_env": None},
    "max_inflight": 16,
    "retention_days": 30,
}

CM0 = dict(C0, mode="required")

Q0 = {
    "v": 1,
    "request_id": I("lsreq", "A"),
    "candidate": {
        "result_id": I("lsres", "A"),
        "binding": {
            "tenant_id": I("lsten", "A"),
            "gateway_id": I("lsgw", "A"),
            "run_id": I("lsrun", "A"),
            "call_id": I("lscall", "A"),
            "tool": "search",
            "adapter": "native",
            "result_ordinal": 0,
        },
        "tool_error": False,
        "blocks": [{"index": 0, "text": "Hello"}],
    },
}


def gen_receipt(n, mode="rules_only"):
    """Receipt generation (spec 19): receipt n uses the nth allocator suffix
    for request/result/call/decision/receipt, text "Hello", time 999+n,
    prev = preceding generated receipt hash; seq 1 is exactly R0."""
    c = chr(0x41 + n - 1)
    config = CM0 if mode == "required" else C0
    candidate = {
        "result_id": I("lsres", c),
        "binding": {
            "tenant_id": I("lsten", "A"),
            "gateway_id": I("lsgw", "A"),
            "run_id": I("lsrun", "A"),
            "call_id": I("lscall", c),
            "tool": "search",
            "adapter": "native",
            "result_ordinal": 0,
        },
        "tool_error": False,
        "blocks": [{"index": 0, "text": "Hello"}],
    }
    envelope = {
        "type": "lexsieve.tool-data.v1",
        "result_id": I("lsres", c),
        "decision_id": I("lsdec", c),
        "receipt_id": I("lsrcp", c),
        "trust": "untrusted",
        "disposition": "pass",
        "provenance": {
            "tool": "search",
            "adapter": "native",
            "content_sha256": H(J(candidate["blocks"])),
        },
        "notice": None,
        "data": candidate["blocks"],
    }
    decision = {
        "decision_id": I("lsdec", c),
        "result_id": I("lsres", c),
        "input_hash": H(J(candidate)),
        "snapshot": {
            "epoch": 1,
            "config_hash": H(J(config)),
            "pack_hash": PH0,
            "model_hash": model_hash(M0) if mode == "required" else None,
            "lexshield_policy_hash": H0,
        },
        "policy_result": {
            "v": 1, "policy_hash": H0, "disposition": "allow", "reason": "POLICY_ALLOW",
        },
        "verdict": "pass",
        "reason": "CLEAN",
        "findings": [],
        "replacements": [],
        "output_hash": H(J(envelope)),
        "quarantine_id": None,
    }
    body = {
        "v": 1,
        "receipt_id": I("lsrcp", c),
        "tenant_id": I("lsten", "A"),
        "gateway_id": I("lsgw", "A"),
        "seq": n,
        "recorded_at_ms": 999 + n,
        "prev_hash": Z if n == 1 else gen_receipt(n - 1, mode)["hash"],
        "decision": decision,
    }
    sig = sign_receipt(body, seed)
    return {"body": body, "hash": sig["hash"], "key_id": I("lskey", "B"), "signature": sig["signature"]}


R0 = gen_receipt(1)
S0 = {
    "v": 1,
    "decision": R0["body"]["decision"],
    "envelope": {
        "type": "lexsieve.tool-data.v1",
        "result_id": I("lsres", "A"),
        "decision_id": I("lsdec", "A"),
        "receipt_id": I("lsrcp", "A"),
        "trust": "untrusted",
        "disposition": "pass",
        "provenance": {
            "tool": "search",
            "adapter": "native",
            "content_sha256": H(J(Q0["candidate"]["blocks"])),
        },
        "notice": None,
        "data": Q0["candidate"]["blocks"],
    },
    "receipt": R0,
    "cached": False,
}
E0 = S0["envelope"]
D0 = R0["body"]["decision"]
