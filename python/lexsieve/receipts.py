"""Receipt hashing/signing domains and chain verification (spec 8, 10).
  receipt_hash = SHA256(UTF8("LexSieve/receipt/v1\\n")   || JCS(ReceiptBody))
  signature    = Ed25519(UTF8("LexSieve/receipt-sign/v1\\n") || HEX_DECODE(receipt_hash))
  pack_hash    = SHA256(UTF8("LexSieve/pack/v1\\n")      || JCS(PackBody))
  pack sig     = Ed25519(UTF8("LexSieve/pack-sign/v1\\n")    || HEX_DECODE(pack_hash))
"""

from .crypto import b64u_decode, b64u_encode, ed25519_sign, ed25519_verify, hex_decode, sha256_hex
from .jcs import jcs

RECEIPT_HASH_DOMAIN = "LexSieve/receipt/v1\n"
RECEIPT_SIGN_DOMAIN = "LexSieve/receipt-sign/v1\n"
PACK_HASH_DOMAIN = "LexSieve/pack/v1\n"
PACK_SIGN_DOMAIN = "LexSieve/pack-sign/v1\n"


def receipt_hash(body):
    return sha256_hex(RECEIPT_HASH_DOMAIN + jcs(body))


def sign_receipt(body, seed):
    h = receipt_hash(body)
    sig = ed25519_sign(seed, RECEIPT_SIGN_DOMAIN.encode("utf-8") + hex_decode(h))
    return {"hash": h, "signature": b64u_encode(sig)}


def pack_hash(body):
    return sha256_hex(PACK_HASH_DOMAIN + jcs(body))


def sign_pack(body, seed):
    h = pack_hash(body)
    sig = ed25519_sign(seed, PACK_SIGN_DOMAIN.encode("utf-8") + hex_decode(h))
    return {"hash": h, "signature": b64u_encode(sig)}


def verify_receipt_with_key(receipt, public_key, expected_prev_hash, expected_seq):
    """verifyReceipt: checks schema, body hash, signature, then chain link —
    in that order. Pure: never fetches a key; key_id is an informational
    label bound only by the caller-supplied public_key."""
    body = receipt["body"]
    if receipt_hash(body) != receipt["hash"]:
        return {"valid": False, "reason": "HASH"}
    msg = RECEIPT_SIGN_DOMAIN.encode("utf-8") + hex_decode(receipt["hash"])
    try:
        sig_ok = ed25519_verify(public_key, msg, b64u_decode(receipt["signature"]))
    except Exception:
        sig_ok = False
    if not sig_ok:
        return {"valid": False, "reason": "SIGNATURE"}
    if body["prev_hash"] != expected_prev_hash or body["seq"] != expected_seq:
        return {"valid": False, "reason": "LINK"}
    return {"valid": True, "reason": "VALID"}


def verify_pack_signature(pack, public_key):
    msg = PACK_SIGN_DOMAIN.encode("utf-8") + hex_decode(pack["hash"])
    try:
        return ed25519_verify(public_key, msg, b64u_decode(pack["signature"]))
    except Exception:
        return False
