"""lexsieve CLI (spec 12). All output is JSON on stdout ending with one LF;
operational diagnostics go to stderr and never contain raw input text.
Exit codes: 0 ok; 10 strip; 20 hold; 2 usage/schema; 3 config/not-ready;
4 io/storage; 5 verification; 6 auth; 7 retryable network; 8 eval/replay.
"""

import os
import re
import secrets
import socket
import sys

from .adapters import receive_wire  # noqa: F401  (parity surface)
from .config import check_config, load_deployment, resolve_path
from .control import rpc_error
from .crypto import b64u_decode, b64u_encode, ed25519_public_from_seed, sha256_hex
from .engine import SYSTEM_CLOCK, Engine
from .errors import ClosedError, NotImplementedError
from .hosted import HostedApiClient
from .ids import csprng_allocator, require_id
from .jcs import jcs, parse_json
from .lexshield import STATIC_POLICY_HASH, StaticLexShield, missing_lexshield_binding
from .packs import activate_pack, config_hash_of, verify_pack
from .receipts import receipt_hash, sign_pack, verify_receipt_with_key
from .rules import compile_pack_rules
from .schema import (
    validate_config,
    validate_pack_body,
    validate_screen_request,
    validate_signed_pack,
    validate_signed_receipt,
    validate_trust_config,
)
from .sqlite import SqliteSink
from .verify import replay as replay_run

VERSION_LINE = "lexsieve 1.0.0 protocol=1"


def exit_for_code(code):
    if code in ("INVALID_REQUEST", "CONFLICT", "LIMIT", "UNSUPPORTED_CONTENT", "INVALID_UTF8"):
        return 2
    if code in ("NOT_READY", "STALE_POLICY", "UNSUPPORTED_VERSION"):
        return 3
    if code in ("NOT_FOUND", "STORAGE_UNAVAILABLE"):
        return 4
    if code == "BAD_SIGNATURE":
        return 5
    if code in ("UNAUTHENTICATED", "FORBIDDEN"):
        return 6
    if code in ("RATE_LIMITED", "CHAIN_GAP", "DEADLINE"):
        return 7
    return 4


class UsageError(Exception):
    pass


# ---------------------------------------------------------------------------
# arg parsing: singleton flags only; repeats/unknowns/positionals -> usage.
# ---------------------------------------------------------------------------

GLOBAL_FLAGS = frozenset({"help", "version", "json", "config"})


class Args:
    def __init__(self):
        self.cmd = []
        self.flags = {}


def parse_args(argv, flag_spec):
    flags = {}
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            name = a[2:]
            kind = flag_spec.get(name)
            if kind is None:
                if name in GLOBAL_FLAGS:
                    kind = "value" if name == "config" else "bool"
                else:
                    raise UsageError(f"unknown flag --{name}")
            if name in flags:
                raise UsageError(f"repeated flag --{name}")
            if kind == "bool":
                flags[name] = True
            else:
                i += 1
                if i >= len(argv):
                    raise UsageError(f"--{name} needs a value")
                flags[name] = argv[i]
        else:
            pos.append(a)
        i += 1
    args = Args()
    args.cmd = pos
    args.flags = flags
    return args


def flag(a, name):
    v = a.flags.get(name)
    return v if isinstance(v, str) else None


def req_flag(a, name):
    v = flag(a, name)
    if v is None:
        raise UsageError(f"missing --{name}")
    return v


def flag_int(a, name, lo, hi):
    raw = req_flag(a, name)
    if not re.match(r"^-?\d+$", raw):
        raise ClosedError("INVALID_REQUEST", f"--{name} not an integer")
    n = int(raw)
    if n < lo or n > hi or abs(n) > 9007199254740991:
        raise ClosedError("INVALID_REQUEST", f"--{name} out of range")
    return n


# ---------------------------------------------------------------------------
# io helpers
# ---------------------------------------------------------------------------

def out(v):
    sys.stdout.write(jcs(v) + "\n")


def read_input(path):
    if path == "-":
        return sys.stdin.buffer.read().decode("utf-8")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        raise ClosedError("NOT_FOUND", f"cannot read {path}") from None


def read_input_bytes(path):
    if path == "-":
        return sys.stdin.buffer.read()
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        raise ClosedError("NOT_FOUND", f"cannot read {path}") from None


def write_output(path, data, replace):
    """create-new by default; --replace permits atomic replace of generated
    files."""
    if path is None or path == "-":
        sys.stdout.write(data)
        return
    tmp = f"{path}.tmp-{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
    except OSError:
        raise ClosedError("STORAGE_UNAVAILABLE", f"cannot write {path}") from None
    try:
        if replace:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)  # create-new: fails EEXIST
            except FileExistsError:
                raise ClosedError("CONFLICT", f"{path} exists; pass --replace") from None
            os.unlink(tmp)
    except ClosedError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ClosedError("STORAGE_UNAVAILABLE", f"cannot write {path}") from e


# ---------------------------------------------------------------------------
# deployment plumbing shared by scan/reload/audit export/telemetry flush
# ---------------------------------------------------------------------------

def open_deployment(config_path):
    dep = load_deployment(config_path)
    if dep["config"]["receipt_sink"]["kind"] != "sqlite":
        raise ClosedError(
            "NOT_READY", "durable_object sink requires a worker host binding"
        )
    sink_path = resolve_path(config_path, dep["config"]["receipt_sink"]["path"])
    os.makedirs(os.path.dirname(sink_path) or ".", exist_ok=True)
    sink = SqliteSink(sink_path)
    try:
        sink.open()
    except ClosedError:
        raise
    except Exception as e:
        raise ClosedError("STORAGE_UNAVAILABLE", str(e)) from e
    dep["sink"] = sink
    return dep


def ensure_active(dep):
    """Verifies the configured pack under trust at current time and
    activates it when the active snapshot does not already pin this hash.
    Idempotent."""
    now = int(SYSTEM_CLOCK.now())
    v = verify_pack(dep["pack"], dep["trust"], now)
    if not v["valid"]:
        raise ClosedError("NOT_READY", f"pack: {v['reason']}")
    return activate_pack(
        dep["sink"], dep["config"], dep["trust"], dep["pack"], now,
        config_hash_of(dep["config"]), STATIC_POLICY_HASH,
    )


def build_engine(dep):
    ls_cfg = dep["config"]["lexshield"]
    lexshield = (
        StaticLexShield()
        if ls_cfg["kind"] == "static"
        else missing_lexshield_binding(ls_cfg["binding"])
    )
    deps = {
        "sink": dep["sink"],
        "clock": SYSTEM_CLOCK,
        "ids": csprng_allocator(),
        "lexshield": lexshield,
        "signer": {"key_id": dep["config"]["signer_key_id"], "seed": dep["signerSeed"]},
    }
    return Engine(dep["config"], deps)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_check_config(a):
    config_path = req_flag(a, "config")
    r = check_config(config_path)
    if r["valid"]:
        out({"v": 1, "valid": True})
    else:
        out({"v": 1, "valid": False, "error": r.get("error") or "INTERNAL"})
    return 0 if r["valid"] else 3


def cmd_scan(a):
    config_path = req_flag(a, "config")
    req = validate_screen_request(parse_json(read_input(req_flag(a, "input"))))
    dep = open_deployment(config_path)
    try:
        ensure_active(dep)
        resp = build_engine(dep).screen(req)
        write_output(
            flag(a, "output"), jcs(resp) + "\n", a.flags.get("replace") is True
        )
        return {"pass": 0, "strip": 10, "hold": 20}[resp["decision"]["verdict"]]
    finally:
        dep["sink"].close()


def cmd_pack_compile(a):
    body = validate_pack_body(parse_json(read_input(req_flag(a, "input"))))
    compile_pack_rules(body["rules"])
    write_output(req_flag(a, "output"), jcs(body), a.flags.get("replace") is True)
    out({"v": 1, "written": True})
    return 0


def cmd_pack_sign(a):
    input_bytes = read_input_bytes(req_flag(a, "input"))
    key_id = require_id("lskey", req_flag(a, "key-id"), "key-id")
    seed_env = req_flag(a, "seed-env")
    seed_b64 = os.environ.get(seed_env)
    if seed_b64 is None:
        raise ClosedError("NOT_READY", f"env {seed_env} not set")
    seed = b64u_decode(seed_b64)
    if len(seed) != 32:
        raise ClosedError("INVALID_REQUEST", "seed must decode to 32 bytes")

    body = validate_pack_body(parse_json(input_bytes.decode("utf-8")))
    # Sign requires the input to be exactly JCS(PackBody); no re-canonicalizing.
    if input_bytes.decode("utf-8") != jcs(body):
        raise ClosedError("INVALID_REQUEST", "input is not exact JCS(PackBody)")
    signed = sign_pack(body, seed)
    pack = {
        "body": body,
        "hash": signed["hash"],
        "key_id": key_id,
        "signature": signed["signature"],
    }
    write_output(req_flag(a, "output"), jcs(pack), a.flags.get("replace") is True)
    out({"v": 1, "written": True})
    return 0


def cmd_pack_verify(a):
    pack = validate_signed_pack(parse_json(read_input(req_flag(a, "input"))))
    trust = validate_trust_config(parse_json(read_input(req_flag(a, "trust"))))
    now_ms = flag_int(a, "now-ms", 0, 9007199254740991)
    r = verify_pack(pack, trust, now_ms)
    out({"v": 1, "valid": r["valid"], "reason": r["reason"]})
    return 0 if r["valid"] else 5


def cmd_pack_pull(a):
    origin = req_flag(a, "origin")
    require_id("lspack", req_flag(a, "pack-id"), "pack-id")
    flag_int(a, "serial", 1, 9007199254740991)
    token_env = req_flag(a, "token-env")
    token = os.environ.get(token_env)
    if token is None:
        raise ClosedError("UNAUTHENTICATED", f"env {token_env} not set")
    # Hosted surface — stubbed per spec 8.2.
    HostedApiClient(origin, token).pack_pull({})
    return 3  # unreachable


def cmd_keygen(a):
    seed = secrets.token_bytes(32)
    out({"v": 1, "seed": b64u_encode(seed), "public_key": b64u_encode(ed25519_public_from_seed(seed))})
    return 0


def _control_socket_path(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = validate_config(parse_json(f.read()))
    if cfg["receipt_sink"]["kind"] != "sqlite":
        raise ClosedError(
            "NOT_READY", "durable_object sink requires a worker host binding"
        )
    return os.path.join(
        os.path.dirname(resolve_path(config_path, cfg["receipt_sink"]["path"])),
        "lexsieve-control.sock",
    )


def cmd_reload(a):
    config_path = os.path.abspath(req_flag(a, "config"))
    sock_path = _control_socket_path(config_path)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(5)
    try:
        conn.connect(sock_path)
    except OSError:
        raise ClosedError("NOT_READY", f"control socket {sock_path} unavailable") from None
    try:
        conn.sendall(
            (jcs({"v": 1, "command": "reload", "config_path": config_path}) + "\n").encode("utf-8")
        )
        conn.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                d = conn.recv(65536)
            except socket.timeout:
                raise ClosedError("DEADLINE", "control socket timeout") from None
            if not d:
                break
            chunks.append(d)
    finally:
        conn.close()
    response = parse_json(b"".join(chunks).decode("utf-8").rstrip("\r\n\t "))
    out(response)
    if isinstance(response, dict) and "error" in response:
        return exit_for_code(response["error"]["code"])
    return 0


def cmd_audit_verify(a):
    trust = validate_trust_config(parse_json(read_input(req_flag(a, "trust"))))
    anchor_seq = flag_int(a, "anchor-seq", 0, 9007199254740991)
    anchor_hash = req_flag(a, "anchor-hash")
    if anchor_hash == "Z":
        anchor_hash = "0" * 64
    if not re.match(r"^[0-9a-f]{64}$", anchor_hash):
        raise ClosedError("INVALID_REQUEST", "anchor-hash must be 64 lowercase hex")

    lines = [l for l in read_input(req_flag(a, "input")).split("\n") if l]
    expected_seq = anchor_seq + 1
    expected_prev = anchor_hash
    head_seq = anchor_seq
    for line in lines:
        try:
            receipt = validate_signed_receipt(parse_json(line))
        except Exception:
            out({"v": 1, "valid": False, "error": "SCHEMA"})
            return 5
        if receipt_hash(receipt["body"]) != receipt["hash"]:
            out({"v": 1, "valid": False, "error": "HASH"})
            return 5
        key = next((k for k in trust["keys"] if k["key_id"] == receipt["key_id"]), None)
        if not key or key["purpose"] != "receipt":
            out({"v": 1, "valid": False, "error": "SCHEMA"})
            return 5
        if key["revoked"]:
            out({"v": 1, "valid": False, "error": "SIGNATURE"})
            return 5
        r = verify_receipt_with_key(
            receipt, b64u_decode(key["public_key"]), expected_prev, expected_seq
        )
        if not r["valid"]:
            out({"v": 1, "valid": False, "error": r["reason"]})
            return 5
        expected_prev = receipt["hash"]
        expected_seq += 1
        head_seq = receipt["body"]["seq"]
    out({"v": 1, "valid": True, "receipts": len(lines), "head_seq": head_seq})
    return 0


def cmd_audit_export(a):
    config_path = req_flag(a, "config")
    from_seq = flag_int(a, "from-seq", 1, 9007199254740991)
    to_seq = flag_int(a, "to-seq", 1, 9007199254740991)
    if from_seq > to_seq:
        raise ClosedError("INVALID_REQUEST", "from_seq <= to_seq required")
    dep = open_deployment(config_path)
    try:
        rows = dep["sink"].receipt_range(
            dep["config"]["tenant_id"], dep["config"]["gateway_id"], from_seq, to_seq
        )
        if len(rows) < to_seq - from_seq + 1:
            raise ClosedError("NOT_FOUND", "receipt range incomplete")
        data = "\n".join(jcs(r) for r in rows) + "\n"
        write_output(req_flag(a, "output"), data, a.flags.get("replace") is True)
        out({"v": 1, "exported": len(rows)})
        return 0
    finally:
        dep["sink"].close()


def cmd_replay(a):
    req = parse_json(read_input(req_flag(a, "input")))
    if not isinstance(req, dict):
        raise ClosedError("INVALID_REQUEST", "replay request")
    o = req
    if (
        o.get("v") != 1
        or "request" not in o
        or "recorded" not in o
        or any(k not in ("v", "request", "recorded") for k in o)
    ):
        raise ClosedError("INVALID_REQUEST", "replay request members")
    config_path = flag(a, "config")
    if config_path is not None:
        # Full replay: re-run the recorded screening under the deployment's
        # pack.
        dep = open_deployment(config_path)
        try:
            ensure_active(dep)
            result = replay_run(
                build_engine(dep),
                {"v": 1, "request": o["request"], "recorded": o["recorded"]},
            )
        finally:
            dep["sink"].close()
    else:
        # Artifact-free replay: recompute the recorded integrity anchors.
        # This detects request/record tampering but does not re-run
        # rules/model.
        request = validate_screen_request(o["request"])
        recorded = o["recorded"]
        diffs = []
        ih = sha256_hex(jcs(request["candidate"]))
        decision = recorded.get("decision") if isinstance(recorded, dict) else None
        if not isinstance(decision, dict) or decision.get("input_hash") != ih:
            diffs.append("input")
        result = {"v": 1, "equal": len(diffs) == 0, "differences": diffs}
    out(result)
    return 0 if result["equal"] else 8


def cmd_eval(a):
    suite = req_flag(a, "suite")
    fixtures_dir = req_flag(a, "fixtures")
    flag_int(a, "seed", 0, 2147483647)
    report_path = req_flag(a, "report")

    try:
        with open(os.path.join(fixtures_dir, "manifest.json"), "r", encoding="utf-8") as f:
            manifest = parse_json(f.read())
    except OSError:
        raise ClosedError("NOT_FOUND", f"no fixture manifest in {fixtures_dir}") from None
    entry = (manifest.get("suites") or {}).get(suite)
    if not entry:
        raise ClosedError("NOT_FOUND", f"suite {suite} not in manifest")
    corpus_path = os.path.join(fixtures_dir, entry["file"])
    raw = read_input_bytes(corpus_path)
    if sha256_hex(raw) != entry["sha256"]:
        raise ClosedError("BAD_SIGNATURE", f"corpus hash mismatch for {suite}")
    corpus = parse_json(raw.decode("utf-8"))
    vectors = corpus["vectors"]

    from .eval.harness import run_vector

    failures = []
    passed = 0
    for v in vectors:
        actual = run_vector(v)
        ek = list(v["expected"].keys())
        ok = all(jcs(actual.get(k)) == jcs(v["expected"][k]) for k in ek) and all(
            k in ek for k in actual.keys()
        )
        if ok:
            passed += 1
        else:
            failures.append(
                {"vector_id": v["id"], "expected": v["expected"], "actual": actual}
            )
    report = {"v": 1, "suite": suite, "passed": passed, "failed": len(failures), "failures": failures}
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(jcs(report) + "\n")
    out({"v": 1, "suite": suite, "passed": passed, "failed": len(failures)})
    return 0 if not failures else 8


def cmd_telemetry_flush(a):
    max_batches = flag_int(a, "max-batches", 1, 256)
    dep = open_deployment(req_flag(a, "config"))
    try:
        if not dep["config"]["telemetry"]["enabled"]:
            raise ClosedError("NOT_READY", "telemetry disabled")
        token_env = dep["config"]["telemetry"]["token_env"]
        token = os.environ.get(token_env)
        if token is None:
            raise ClosedError("UNAUTHENTICATED", f"env {token_env} not set")
        client = HostedApiClient(dep["config"]["telemetry"]["origin"], token)
        due = dep["sink"].spool_due(int(SYSTEM_CLOCK.now()), max_batches)
        acked = 0
        for row in due:
            row["state"] = "sending"
            dep["sink"].spool_update(row)
            try:
                client.telemetry_ingest(parse_json(row["json"]))
                row["state"] = "acknowledged"
                acked += 1
            except Exception:
                # Hosted ingest is not implemented in OSS core; auth/schema
                # failures are not auto-retried per spec — everything stays
                # pending with backoff.
                row["state"] = "pending"
                row["attempts"] += 1
                row["next_attempt_ms"] = int(SYSTEM_CLOCK.now()) + 1000 * 2 ** min(
                    row["attempts"], 6
                )
            dep["sink"].spool_update(row)
        remaining = dep["sink"].spool_count() - acked
        out({"v": 1, "acknowledged": acked, "remaining": remaining})
        return 7 if remaining > 0 else 0
    finally:
        dep["sink"].close()


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

SPECS = {
    "check-config": {"config": "value"},
    "scan": {"config": "value", "input": "value", "output": "value", "replace": "bool"},
    "pack compile": {"input": "value", "output": "value", "replace": "bool"},
    "pack sign": {"input": "value", "key-id": "value", "seed-env": "value", "output": "value", "replace": "bool"},
    "pack verify": {"input": "value", "trust": "value", "now-ms": "value"},
    "pack pull": {"origin": "value", "pack-id": "value", "serial": "value", "token-env": "value", "trust": "value", "output": "value", "replace": "bool"},
    "keygen": {},
    "reload": {"config": "value"},
    "audit verify": {"input": "value", "trust": "value", "anchor-seq": "value", "anchor-hash": "value"},
    "audit export": {"config": "value", "from-seq": "value", "to-seq": "value", "output": "value", "replace": "bool"},
    "replay": {"input": "value", "config": "value"},
    "eval": {"suite": "value", "fixtures": "value", "seed": "value", "report": "value"},
    "telemetry flush": {"config": "value", "max-batches": "value"},
}

HELP = """lexsieve — tool-output injection scrubber (protocol v1)

usage: lexsieve <command> [flags]
  check-config --config P
  scan --input -|P --config P [--output P] [--replace]
  pack compile --input P --output P
  pack sign --input P --key-id K --seed-env E --output P
  pack verify --input P --trust T --now-ms N
  pack pull --origin O --pack-id ID --serial N --token-env E --trust T --output P
  keygen
  reload --config P
  audit verify --input P --trust T --anchor-seq N --anchor-hash H
  audit export --config P --from-seq A --to-seq B --output P
  replay --input P [--config P]
  eval --suite S --fixtures D --seed N --report P
  telemetry flush --config P --max-batches N
global: --help --version --json --config P
"""

_DISPATCH = {
    "check-config": cmd_check_config,
    "scan": cmd_scan,
    "pack compile": cmd_pack_compile,
    "pack sign": cmd_pack_sign,
    "pack verify": cmd_pack_verify,
    "pack pull": cmd_pack_pull,
    "keygen": cmd_keygen,
    "reload": cmd_reload,
    "audit verify": cmd_audit_verify,
    "audit export": cmd_audit_export,
    "replay": cmd_replay,
    "eval": cmd_eval,
    "telemetry flush": cmd_telemetry_flush,
}


def main(argv):
    try:
        # Command selection: first positional, plus a second only when the
        # pair is a known two-word command (pack compile, audit verify, ...).
        first = argv[0] if argv else ""
        if len(argv) > 1 and not argv[1].startswith("-") and f"{first} {argv[1]}" in SPECS:
            cmd = f"{first} {argv[1]}"
            rest_start = 2
        else:
            cmd = first
            rest_start = 1
        rest = argv[rest_start:]

        if "--help" in argv or (argv and argv[0] == "-h") or cmd == "":
            sys.stdout.write(HELP)
            return 0
        if "--version" in argv:
            sys.stdout.write(VERSION_LINE + "\n")
            return 0
        if cmd not in SPECS:
            sys.stderr.write(f"lexsieve: unknown command {cmd or '(none)'}\n")
            return 2
        a = parse_args(rest, SPECS[cmd])
        if len(a.cmd) != 0:
            raise UsageError("positional extras")
        return _DISPATCH[cmd](a)
    except UsageError as e:
        sys.stderr.write(f"lexsieve: {e}\n")
        return 2
    except NotImplementedError as e:
        out(rpc_error("NOT_READY"))
        sys.stderr.write(f"lexsieve: {e}\n")
        return 3
    except ClosedError as e:
        out(rpc_error(e.code))
        sys.stderr.write(f"lexsieve: {e}\n")
        return exit_for_code(e.code)
    except KeyboardInterrupt:
        return 130
    except Exception:
        out(rpc_error("INTERNAL"))
        sys.stderr.write("lexsieve: internal error\n")
        return 4


def run():
    sys.exit(main(sys.argv[1:]))
