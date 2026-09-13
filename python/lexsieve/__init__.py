"""LexSieve OSS core — deterministic tool-output injection scrubber.

Public API surface mirrors the TypeScript package index (src/index.ts).
"""

from .adapters import (
    COMPLETION_TIMEOUT_MS,
    FAILURE_ENVELOPE,
    TEXT_CAP,
    WIRE_CAP,
    check_block_bounds,
    decode_wire,
    failure_envelope_json,
    mcp_extract,
    mcp_serialize,
    mcp_serialize_failure,
    native_extract,
    openai_extract,
    openai_serialize,
    openai_serialize_failure,
    receive_wire,
)
from .cli import VERSION_LINE, main as cli_main
from .config import check_config, load_config, load_deployment, resolve_path
from .control import ControlServer
from .crypto import (
    b64u_decode,
    b64u_encode,
    ed25519_public_from_seed,
    ed25519_sign,
    ed25519_verify,
    sha256_hex,
)
from .engine import BUDGET, SYSTEM_CLOCK, Engine
from .errors import ClosedError, NotImplementedError
from .hosted import HostedApiClient
from .ids import csprng_allocator, is_valid_id
from .jcs import jcs, parse_json
from .lexshield import STATIC_POLICY_HASH, AxionLexShield, StaticLexShield
from .model import featurize, model_hash, score, validate_model_artifact
from .packs import CORE_VERSION, activate_pack, config_hash_of, verify_pack
from .sink import MemorySink
from .sqlite import SqliteSink
from .telemetry import TenantTelemetryStore
from .verify import replay, verify_receipt, verify_receipt_trust

__version__ = "1.0.0"

__all__ = [
    "AxionLexShield",
    "BUDGET",
    "COMPLETION_TIMEOUT_MS",
    "CORE_VERSION",
    "ClosedError",
    "ControlServer",
    "Engine",
    "FAILURE_ENVELOPE",
    "HostedApiClient",
    "MemorySink",
    "NotImplementedError",
    "STATIC_POLICY_HASH",
    "SYSTEM_CLOCK",
    "SqliteSink",
    "StaticLexShield",
    "TEXT_CAP",
    "TenantTelemetryStore",
    "VERSION_LINE",
    "WIRE_CAP",
    "activate_pack",
    "b64u_decode",
    "b64u_encode",
    "check_block_bounds",
    "check_config",
    "cli_main",
    "config_hash_of",
    "csprng_allocator",
    "decode_wire",
    "ed25519_public_from_seed",
    "ed25519_sign",
    "ed25519_verify",
    "failure_envelope_json",
    "featurize",
    "is_valid_id",
    "jcs",
    "load_config",
    "load_deployment",
    "main",
    "mcp_extract",
    "mcp_serialize",
    "mcp_serialize_failure",
    "model_hash",
    "native_extract",
    "openai_extract",
    "openai_serialize",
    "openai_serialize_failure",
    "parse_json",
    "receive_wire",
    "replay",
    "resolve_path",
    "score",
    "sha256_hex",

    "validate_model_artifact",
    "verify_pack",
    "verify_receipt",
    "verify_receipt_trust",
    "__version__",
]
