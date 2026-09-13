"""Configuration loading (spec 8.1). Paths resolve relative to the config
file's directory, never process cwd. The signer seed is read from the named
environment variable at startup and each reload, never serialized.
"""

import os

from .crypto import (
    RFC8032_TEST_PUB_HEX,
    RFC8032_TEST_SEED_HEX,
    b64u_decode,
    ed25519_public_from_seed,
)
from .errors import ClosedError
from .jcs import parse_json
from .packs import verify_pack_untimed
from .schema import validate_config, validate_signed_pack, validate_trust_config


def _read_json_file(path, what):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        raise ClosedError("NOT_READY", f"cannot read {what}: {e}") from e
    return parse_json(raw)


def resolve_path(config_path, p):
    return os.path.join(os.path.dirname(config_path), p)


def load_config(config_path):
    return validate_config(_read_json_file(config_path, "config"))


def load_deployment(config_path, allow_fixture_key=False):
    """Loads and cross-checks config + trust + pack + signer seed. When
    `allow_fixture_key` is false (always, outside the test runner), the
    RFC8032 fixture key material is rejected."""
    config = load_config(config_path)
    trust = validate_trust_config(
        _read_json_file(resolve_path(config_path, config["trust_file"]), "trust")
    )
    pack = validate_signed_pack(
        _read_json_file(resolve_path(config_path, config["pack_file"]), "pack")
    )

    env_name = config["signer_seed_env"]
    seed_b64 = os.environ.get(env_name)
    if seed_b64 is None:
        raise ClosedError("NOT_READY", f"env {env_name} not set")
    try:
        seed = b64u_decode(seed_b64)
    except ClosedError:
        raise ClosedError("NOT_READY", f"env {env_name} not base64url") from None
    if len(seed) != 32:
        raise ClosedError("NOT_READY", "signer seed must be 32 bytes")
    derived_pub = ed25519_public_from_seed(seed)
    if not allow_fixture_key:
        if seed.hex() == RFC8032_TEST_SEED_HEX:
            raise ClosedError("NOT_READY", "fixture seed prohibited in production")
        if derived_pub.hex() == RFC8032_TEST_PUB_HEX:
            raise ClosedError("NOT_READY", "fixture public key prohibited in production")
    trust_entry = next(
        (k for k in trust["keys"] if k["key_id"] == config["signer_key_id"]), None
    )
    if not trust_entry or trust_entry["purpose"] != "receipt":
        raise ClosedError("NOT_READY", "signer_key_id not a receipt key in trust")
    if trust_entry["revoked"]:
        raise ClosedError("NOT_READY", "signer key revoked")
    if b64u_decode(trust_entry["public_key"]) != derived_pub:
        raise ClosedError(
            "NOT_READY", "signer seed does not match signer_key_id trust entry"
        )
    return {
        "config": config,
        "configPath": config_path,
        "trust": trust,
        "pack": pack,
        "signerSeed": seed,
        "signerKeyId": config["signer_key_id"],
    }


def check_config(config_path, allow_fixture_key=False):
    """Full check-config: schema + files + pack structural/signature
    verification + signer consistency. Does not check the pack validity
    window."""
    try:
        dep = load_deployment(config_path, allow_fixture_key)
        v = verify_pack_untimed(dep["pack"], dep["trust"])
        if not v["valid"]:
            return {
                "valid": False,
                "error": "BAD_SIGNATURE" if v["reason"] == "SIGNATURE" else "INVALID_REQUEST",
            }
        return {"valid": True}
    except ClosedError as e:
        return {"valid": False, "error": e.code}
    except Exception:
        return {"valid": False, "error": "INTERNAL"}
