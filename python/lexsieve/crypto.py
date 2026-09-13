"""Cryptographic primitives: SHA-256, Ed25519 (RFC 8032), base64url, CSPRNG.

Ed25519 uses the `cryptography` package (OpenSSL EVP), which implements
RFC 8032 deterministic signatures — identical outputs to Node's node:crypto.
"""

import base64
import hashlib
import re
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import ClosedError

B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

_B64U_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_ANY_RE = re.compile(r"^[0-9a-fA-F]*$")


def sha256(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return sha256(data).hex()


def b64u_encode(b):
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    if not _B64U_RE.match(s):
        raise ClosedError("INVALID_REQUEST", "bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hex_decode(s):
    if not _HEX_RE.match(s) and not _HEX_ANY_RE.match(s):
        raise ClosedError("INVALID_REQUEST", "bad hex")
    # mirrors Buffer.from(s,'hex'): decode maximal complete pairs from start
    return bytes(int(s[i : i + 2], 16) for i in range(0, len(s) - 1, 2))


def ed25519_public_from_seed(seed):
    if len(seed) != 32:
        raise ClosedError("INVALID_REQUEST", "seed must be 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(bytes(seed))
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_sign(seed, message):
    if len(seed) != 32:
        raise ClosedError("INVALID_REQUEST", "seed must be 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(bytes(seed))
    return sk.sign(bytes(message))


def ed25519_verify(public_key, message, signature):
    try:
        if len(public_key) != 32:
            return False
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(signature), bytes(message)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# RFC 8032 test key material — production startup MUST reject it (spec 8.1).
RFC8032_TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_TEST_PUB_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

NANOID_ALPHABET = B64U


def nanoid21():
    """21-char nanoid from the spec's locked alphabet, CSPRNG bytes only.
    256 % 64 == 0, so no modulo bias; 32 bytes is always enough."""
    out = []
    for b in secrets.token_bytes(32):
        out.append(NANOID_ALPHABET[b & 0x3F])
        if len(out) == 21:
            break
    return "".join(out)
