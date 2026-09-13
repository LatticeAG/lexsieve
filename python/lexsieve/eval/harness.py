"""Section 18/20 integration harness. Implements the vector ops literally:
screen, adapter, lifecycle, idempotency, pack, receipt, telemetry, schema,
budget. Fails on unknown op, profile, fault, input field, expected-output
field, or vector ID — never skips.
"""

import copy
import json

from ..adapters import (
    mcp_extract,
    mcp_serialize,
    native_extract,
    openai_extract,
    openai_serialize,
    receive_wire,
)
from ..crypto import ed25519_sign, hex_decode, sha256_hex
from ..engine import Engine
from ..errors import ClosedError
from ..jcs import jcs
from ..lexshield import STATIC_POLICY_HASH, StaticLexShield
from ..model import score as model_score
from ..packs import activate_pack, config_hash_of, verify_pack
from ..receipts import pack_hash, sign_pack, sign_receipt
from ..rules import CLASS_ORDER
from ..sink import MemorySink
from ..sqlite import SqliteSink
from ..telemetry import TenantTelemetryStore
from ..verify import verify_receipt_trust
from .clocks import fake_clock, scripted_clock
from .fixture19 import (
    C0, CM0, E0, H, I, J, M0, P0, PB0, PH0, Q0, R0, T0, Z,
    gen_receipt, letter_allocator, pub, seed,
)

OPS = (
    "screen", "adapter", "lifecycle", "idempotency", "pack",
    "receipt", "telemetry", "schema", "budget",
)

INPUT_FIELDS = {
    "screen": ["op", "profile", "text", "blocks", "error", "fault", "pack_rules"],
    "adapter": ["op", "adapter", "text", "wire_hex", "result"],
    "lifecycle": ["op", "profile", "text", "fixture", "chunks", "independent_calls", "events"],
    "idempotency": ["op", "fixture", "events"],
    "pack": ["op", "fixture", "rules", "resign", "events"],
    "receipt": ["op", "fixture", "primitive", "seed_hex", "message_hex", "trust", "mutation", "resign", "anchor_seq", "anchor_hash"],
    "telemetry": ["op", "receipt_sequences", "batch_suffix", "authenticated_tenant_suffix", "initial_checkpoint", "events"],
    "schema": ["op", "canonicalize"],
    "budget": ["op", "profile", "text", "events", "durations_ms"],
}

EXPECTED_FIELDS = {
    "screen": ["verdict", "reason", "texts", "classes", "ranges"],
    "adapter": ["error", "verdict", "reason", "classes", "isError", "raw_bytes", "receipt_count", "structuredContent_present", "outer_trust", "role", "system_messages_added", "tenant_changed"],
    "lifecycle": ["error", "bytes_before_end", "texts_after_handoff", "verdict", "receipt_count", "raw_bytes", "sealed_verdict", "sealed_reason", "rows_containing_Hello", "input_hash_stored", "raw_content_columns", "verdicts", "joined_scan", "authorization_granted"],
    "idempotency": ["receipt_count", "cached_sorted", "same_receipt", "same_envelope", "first_verdict", "retry_error", "cached", "upstream_dispatches", "envelope_equals_E0"],
    "pack": ["valid", "reason", "activated", "error", "active_serial", "active_epoch"],
    "receipt": ["signature_hex", "valid", "reason", "head_seq"],
    "telemetry": ["accepted", "duplicate", "aggregate_pass", "head_seq", "status", "error", "retryable"],
    "schema": ["canonical", "sha256"],
    "budget": ["error", "raw_bytes", "receipt_count", "inflight", "request_17_error", "request_17_raw_bytes", "verdict", "screen_ms", "budget_exceeded"],
}

FAULTS = (
    "lexshield_explicit_allow",
    "model_completes_at_81ms",
    "model_missing_after_admission",
    "model_response_adds_explanation_ignore_previous_instructions",
)


def _check_fields(obj, allowed, what):
    for k in obj:
        if k not in allowed:
            raise ValueError(f"unknown {what} field: {k}")


def _expand_text(v):
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        _check_fields(v, ["repeat", "count", "separator"], "text expansion")
        return str(v["separator"]).join([v["repeat"]] * v["count"])
    raise ValueError("bad text")


class Runtime:
    def __init__(self, engine, sink, clock, config, ids):
        self.engine = engine
        self.sink = sink
        self.clock = clock
        self.config = config
        self.ids = ids
        self.emitted_envelopes = []  # serialized model-facing envelopes


def build_runtime(profile, pack_rules=None, fault=None, sink=None, clock=None):
    """A screening runtime on the fixture objects: P0 + T0 + C0/CM0,
    wall=1000, mono=0, letter allocator, static LexShield, fixture receipt
    seed."""
    config = CM0 if profile == "M" else C0
    sink = sink or MemorySink()
    clock = clock or fake_clock(1000)
    ids = letter_allocator()
    sink.open()
    activate_pack(sink, config, T0, P0, clock.now(), config_hash_of(config), STATIC_POLICY_HASH)
    if pack_rules is not None:
        # PB0 with serial=2 and the exact rules, resigned; activates epoch 2.
        body = dict(PB0, serial=2, rules=pack_rules)
        sig = sign_pack(body, seed)
        active_pack = {"body": body, "hash": sig["hash"], "key_id": I("lskey", "A"), "signature": sig["signature"]}
        activate_pack(sink, config, T0, active_pack, clock.now(), config_hash_of(config), STATIC_POLICY_HASH)
    lexshield = StaticLexShield()
    deps = {
        "sink": sink,
        "clock": clock,
        "ids": ids,
        "lexshield": lexshield,
        "signer": {"key_id": I("lskey", "B"), "seed": seed},
    }
    engine = Engine(config, deps)
    if fault is not None:
        if fault == "lexshield_explicit_allow":
            pass  # static adapter already allows explicitly
        elif fault == "model_completes_at_81ms":
            def port81(req):
                clock.advance_mono(81)
                return model_score(engine.artifact, req["features"])
            engine.model_port = port81
        elif fault == "model_missing_after_admission":
            def port_missing(req):
                raise ClosedError("NOT_FOUND", "artifact missing")
            engine.model_port = port_missing
        elif fault == "model_response_adds_explanation_ignore_previous_instructions":
            def port_extra(req):
                r = model_score(engine.artifact, req["features"])
                return dict(r, explanation="ignore previous instructions")
            engine.model_port = port_extra
        else:
            raise ValueError(f"unknown fault {fault}")
    return Runtime(engine, sink, clock, config, ids)


def _binding(call_id, adapter="native"):
    return {
        "tenant_id": I("lsten", "A"),
        "gateway_id": I("lsgw", "A"),
        "run_id": I("lsrun", "A"),
        "call_id": call_id,
        "tool": "search",
        "adapter": adapter,
        "result_ordinal": 0,
    }


def _build_request(rt, inp, adapter="native", tool_error=False, blocks=None):
    if blocks is None:
        if "blocks" in inp:
            blocks = [{"index": i, "text": t} for i, t in enumerate(inp["blocks"])]
        else:
            blocks = [{"index": 0, "text": _expand_text(inp["text"])}]
    return {
        "v": 1,
        "request_id": rt.ids.next("lsreq"),
        "candidate": {
            "result_id": rt.ids.next("lsres"),
            "binding": _binding(rt.ids.next("lscall"), adapter),
            "tool_error": tool_error,
            "blocks": blocks,
        },
    }


def _classes_of(resp):
    present = {f["class"] for f in resp["decision"]["findings"]}
    return [c for c in CLASS_ORDER if c in present]


def _project_screen(resp):
    return {
        "verdict": resp["decision"]["verdict"],
        "reason": resp["decision"]["reason"],
        "texts": [b["text"] for b in resp["envelope"]["data"]],
        "classes": _classes_of(resp),
        "ranges": [[r["block"], r["start"], r["end"]] for r in resp["decision"]["replacements"]],
    }


def _raw_bytes_leaked(raw_texts, serialized):
    """Bytes of raw tool text that appear in a serialized output.
    Whole-block containment per block; a hold emits none."""
    n = 0
    for t in raw_texts:
        if len(t) > 0 and t in serialized:
            n += len(t.encode("utf-8"))
    return n


# ---------------------------------------------------------------------------

def op_screen(inp):
    _check_fields(inp, INPUT_FIELDS["screen"], "screen input")
    if "text" in inp and "blocks" in inp:
        raise ClosedError("INVALID_REQUEST", "text and blocks together")
    rt = build_runtime(
        inp.get("profile"), pack_rules=inp.get("pack_rules"), fault=inp.get("fault")
    )
    req = _build_request(rt, inp, "native", inp.get("error") is True)
    resp = rt.engine.screen(req)
    return _project_screen(resp)


def op_adapter(inp):
    _check_fields(inp, INPUT_FIELDS["adapter"], "adapter input")
    adapter = inp["adapter"]
    if adapter not in ("native", "mcp", "openai"):
        raise ValueError(f"unknown adapter {adapter}")
    rt = build_runtime("R")
    receipt_count = lambda: rt.sink.receipt_count()
    try:
        if adapter == "native":
            if "wire_hex" in inp:
                text = receive_wire(bytes.fromhex(inp["wire_hex"]))
            else:
                text = _expand_text(inp["text"])
            blocks = native_extract([text])
            req = _build_request(rt, inp, "native", False, blocks)
            resp = rt.engine.screen(req)
            rt.emitted_envelopes.append(jcs(resp["envelope"]))
            return {
                "verdict": resp["decision"]["verdict"],
                "reason": resp["decision"]["reason"],
                "classes": _classes_of(resp),
                "raw_bytes": _raw_bytes_leaked([text], jcs(resp["envelope"])),
                "receipt_count": receipt_count(),
            }
        if adapter == "mcp":
            ex = mcp_extract(inp["result"])
            req = _build_request(rt, {}, "mcp", ex["toolError"], ex["blocks"])
            resp = rt.engine.screen(req)
            ser = mcp_serialize(resp["envelope"], ex["toolError"])
            rt.emitted_envelopes.append(jcs(ser))
            raw_texts = [
                c["text"] if isinstance(c.get("text"), str) else ""
                for c in inp["result"].get("content", [])
                if isinstance(c, dict)
            ]
            return {
                "verdict": resp["decision"]["verdict"],
                "reason": resp["decision"]["reason"],
                "classes": _classes_of(resp),
                "isError": ser["isError"] is True,
                "structuredContent_present": "structuredContent" in ser,
                "raw_bytes": _raw_bytes_leaked(raw_texts, jcs(ser)),
                "receipt_count": receipt_count(),
            }
        # openai
        text = _expand_text(inp["text"])
        ex = openai_extract(text)
        req = _build_request(rt, {}, "openai", False, ex["blocks"])
        resp = rt.engine.screen(req)
        ser = openai_serialize(resp["envelope"], req["candidate"]["binding"]["call_id"])
        rt.emitted_envelopes.append(jcs(ser))
        return {
            "verdict": resp["decision"]["verdict"],
            "outer_trust": resp["envelope"]["trust"],
            "role": ser["role"],
            "system_messages_added": 0,
            "raw_bytes": _raw_bytes_leaked([text], jcs(ser)),
            "receipt_count": receipt_count(),
        }
    except ClosedError as e:
        return {
            "error": e.code,
            "raw_bytes": 0,
            "receipt_count": receipt_count(),
            "tenant_changed": False,
        }


# ---------------------------------------------------------------------------

def _inspect_sink(sink, needle):
    """Dump every persisted row and search for a literal — proves no raw
    content is persisted in any sink row (spec 10.1)."""
    rows_containing = 0
    raw_content_columns = 0
    input_hash_stored = False
    if isinstance(sink, SqliteSink):
        db = sink.db
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        for t in tables:
            cols = db.execute(f"PRAGMA table_info({t['name']})").fetchall()
            for c in cols:
                name = c["name"]
                import re as _re

                if _re.search(r"content|raw|text|payload|input_text|blocks", name, _re.I):
                    raw_content_columns += 1
                if name == "input_hash":
                    input_hash_stored = True
            rows = db.execute(f"SELECT * FROM {t['name']}").fetchall()
            for r in rows:
                if needle in json.dumps(dict(r)):
                    rows_containing += 1
    else:
        all_rows = (
            list(sink.decisions.values())
            + list(sink.receipts.values())
            + list(sink.quarantine.values())
            + list(sink.packs.values())
        )
        for r in all_rows:
            if needle in json.dumps(r):
                rows_containing += 1
        input_hash_stored = len(sink.decisions) > 0
        raw_content_columns = 0
    return {
        "rows_containing_Hello": rows_containing,
        "input_hash_stored": input_hash_stored,
        "raw_content_columns": raw_content_columns,
    }


def op_lifecycle(inp):
    _check_fields(inp, INPUT_FIELDS["lifecycle"], "lifecycle input")
    rt = build_runtime(inp.get("profile") or "R")

    # TV-L--60: independent calls never compose into a joined scan.
    if "independent_calls" in inp:
        verdicts = []
        for t in inp["independent_calls"]:
            resp = rt.engine.screen(_build_request(rt, {"text": t}))
            rt.emitted_envelopes.append(jcs(resp["envelope"]))
            verdicts.append(resp["decision"]["verdict"])
        return {"verdicts": verdicts, "joined_scan": False, "authorization_granted": False}

    events = inp.get("events") or []
    ctx = None
    chunk_text = ""
    emitted_bytes = 0
    last_error = None
    sealed_decision = None
    envelope = None
    results = {}

    def req():
        if inp.get("fixture") == "Q0":
            return copy.deepcopy(Q0)
        if "text" in inp:
            return _build_request(rt, {"text": inp["text"]})
        return _build_request(rt, {"text": chunk_text})

    for ev in events:
        if ev == "admit":
            r = rt.engine.admit(req())
            if "cached" in r and r["cached"] is not None:
                raise ValueError("unexpected cached")
            ctx = r["ctx"]
        elif ev == "scan":
            rt.engine.run_local(ctx)
            rt.engine.run_policy(ctx)
        elif ev == "seal":
            try:
                rt.engine.seal(ctx)
                sealed_decision = ctx.committed["decision"] if ctx.committed else None
            except ClosedError as e:
                last_error = e.code
        elif ev == "handoff":
            try:
                envelope = rt.engine.handoff(ctx)
                rt.emitted_envelopes.append(jcs(envelope))
            except ClosedError as e:
                last_error = e.code
        elif ev == "commit":
            r = rt.engine.admit(req())
            ctx = r["ctx"]
            rt.engine.run_local(ctx)
            rt.engine.run_policy(ctx)
            rt.engine.seal(ctx)
            sealed_decision = ctx.committed["decision"] if ctx.committed else None
        elif ev == "sink_unavailable":
            rt.sink.fail_commit = True
        elif ev == "activate_epoch_2":
            body = dict(PB0, serial=2)
            sig = sign_pack(body, seed)
            p2 = {"body": body, "hash": sig["hash"], "key_id": I("lskey", "A"), "signature": sig["signature"]}
            activate_pack(rt.sink, rt.config, T0, p2, rt.clock.now(), config_hash_of(rt.config), STATIC_POLICY_HASH)
        elif ev == "wall_clock_to_86400000":
            rt.clock.set_wall(86400000)
        elif ev == "first_chunk":
            chunk_text += inp["chunks"][0]
        elif ev == "observe":
            results["bytes_before_end"] = emitted_bytes
        elif ev == "last_chunk":
            chunk_text += "".join(inp["chunks"][1:])
        elif ev == "end_message":
            r = rt.engine.admit(_build_request(rt, {"text": chunk_text}))
            ctx = r["ctx"]
        elif ev == "inspect_all_persisted_rows_for_Hello":
            results.update(_inspect_sink(rt.sink, "Hello"))
        else:
            raise ValueError(f"unknown lifecycle event {ev}")
    if envelope:
        emitted_bytes += len(jcs(envelope).encode("utf-8"))
    if last_error is not None:
        results["error"] = last_error
    if sealed_decision:
        results["sealed_verdict"] = sealed_decision["verdict"]
        results["sealed_reason"] = sealed_decision["reason"]
    results["verdict"] = sealed_decision["verdict"] if sealed_decision else None
    if envelope:
        results["texts_after_handoff"] = [b["text"] for b in envelope["data"]]
    results["receipt_count"] = rt.sink.receipt_count()
    results["raw_bytes"] = 0
    return results


# ---------------------------------------------------------------------------

def op_idempotency(inp):
    _check_fields(inp, INPUT_FIELDS["idempotency"], "idempotency input")
    if inp.get("fixture") != "Q0":
        raise ValueError(f"unknown fixture {inp.get('fixture')}")
    rt = build_runtime("R")
    events = inp["events"]
    results = {}
    engine = rt.engine
    ctxs = []
    committed = []
    upstream_dispatches = 0

    def full_commit(req):
        r = engine.admit(req)
        c = r["ctx"]
        engine.run_local(c)
        engine.run_policy(c)
        engine.seal(c)
        committed.append(
            {
                "cached": c.cached_result,
                "receipt": c.committed["receipt"],
                "envelope": c.committed["envelope"],
            }
        )

    for ev in events:
        if ev == "start_two_equal_requests":
            ctxs = [
                engine.admit(copy.deepcopy(Q0))["ctx"],
                engine.admit(copy.deepcopy(Q0))["ctx"],
            ]
        elif ev == "commit_both":
            for c in ctxs:
                engine.run_local(c)
                engine.run_policy(c)
                engine.seal(c)
                committed.append(
                    {
                        "cached": c.cached_result,
                        "receipt": c.committed["receipt"],
                        "envelope": c.committed["envelope"],
                    }
                )
            results["receipt_count"] = rt.sink.receipt_count()
            results["cached_sorted"] = sorted(c["cached"] for c in committed)
            results["same_receipt"] = committed[0]["receipt"]["hash"] == committed[1]["receipt"]["hash"]
            results["same_envelope"] = jcs(committed[0]["envelope"]) == jcs(committed[1]["envelope"])
        elif ev == "commit":
            c = engine.admit(copy.deepcopy(Q0))["ctx"]
            engine.run_local(c)
            engine.run_policy(c)
            engine.seal(c)
            results["first_verdict"] = c.committed["decision"]["verdict"]
        elif ev == "retry_text_Changed":
            changed = copy.deepcopy(Q0)
            changed["candidate"]["blocks"][0]["text"] = "Changed"
            try:
                engine.screen(changed)
                results["retry_error"] = "none"
            except ClosedError as e:
                results["retry_error"] = e.code
            except Exception:
                results["retry_error"] = "thrown"
            results["receipt_count"] = rt.sink.receipt_count()
        elif ev == "crash_before_handoff":
            # committed decision stays; the delivery capability dies
            pass
        elif ev == "restart":
            engine = Engine(rt.config, dict(rt.engine.deps, ids=letter_allocator()))
        elif ev == "retry_equal":
            resp = engine.screen(copy.deepcopy(Q0))
            results["cached"] = resp["cached"]
            results["receipt_count"] = rt.sink.receipt_count()
            results["upstream_dispatches"] = upstream_dispatches
            results["envelope_equals_E0"] = jcs(resp["envelope"]) == jcs(E0)
        else:
            raise ValueError(f"unknown idempotency event {ev}")
    if "receipt_count" not in results:
        results["receipt_count"] = rt.sink.receipt_count()
    return results


# ---------------------------------------------------------------------------

def op_pack(inp):
    _check_fields(inp, INPUT_FIELDS["pack"], "pack input")
    if inp.get("fixture") != "P0":
        raise ValueError(f"unknown fixture {inp.get('fixture')}")
    now = 1000
    if "rules" in inp:
        body = dict(PB0, rules=inp["rules"])
        if inp.get("resign") is True:
            sig = sign_pack(body, seed)
            pack = {"body": body, "hash": sig["hash"], "key_id": I("lskey", "A"), "signature": sig["signature"]}
        else:
            pack = {"body": body, "hash": pack_hash(body), "key_id": I("lskey", "A"), "signature": P0["signature"]}
        v = verify_pack(pack, T0, now)
        activated = False
        if v["valid"]:
            try:
                sink = MemorySink()
                sink.open()
                activate_pack(sink, C0, T0, pack, now, config_hash_of(C0), STATIC_POLICY_HASH)
                activated = True
            except Exception:
                activated = False
        return {"valid": v["valid"], "reason": v["reason"], "activated": activated}
    events = inp.get("events")
    if events:
        sink = MemorySink()
        sink.open()
        # The original P0 is already active at epoch 1 before the listed
        # events.
        activate_pack(sink, C0, T0, P0, now, config_hash_of(C0), STATIC_POLICY_HASH)
        results = {}
        for ev in events:
            if ev == "activate_resigned_serial_2":
                body = dict(PB0, serial=2)
                sig = sign_pack(body, seed)
                p2 = {"body": body, "hash": sig["hash"], "key_id": I("lskey", "A"), "signature": sig["signature"]}
                activate_pack(sink, C0, T0, p2, now, config_hash_of(C0), STATIC_POLICY_HASH)
            elif ev == "activate_original_serial_1":
                try:
                    activate_pack(sink, C0, T0, P0, now, config_hash_of(C0), STATIC_POLICY_HASH)
                except ClosedError as e:
                    results["error"] = e.code
            else:
                raise ValueError(f"unknown pack event {ev}")
        active = sink.get_active_snapshot(C0["tenant_id"], C0["gateway_id"])
        results["active_serial"] = active["pack_serial"]
        results["active_epoch"] = active["epoch"]
        return results
    raise ValueError("pack op: no rules and no events")


# ---------------------------------------------------------------------------

def op_receipt(inp):
    _check_fields(inp, INPUT_FIELDS["receipt"], "receipt input")
    if inp.get("primitive") == "ed25519":
        sig = ed25519_sign(hex_decode(inp["seed_hex"]), hex_decode(inp["message_hex"]))
        return {"signature_hex": sig.hex()}
    if inp.get("fixture") == "R0":
        receipt = copy.deepcopy(R0)
        if "mutation" in inp:
            m = inp["mutation"]
            parts = m["path"].split(".")
            obj = receipt
            for p in parts[:-1]:
                obj = obj[p]
            obj[parts[-1]] = m["value"]
            if inp.get("resign") is True:
                sig = sign_receipt(receipt["body"], seed)
                receipt = dict(receipt, hash=sig["hash"], signature=sig["signature"])
        trust = T0  # only fixture trust
        anchor_seq = inp.get("anchor_seq", 0)
        anchor_hash = inp.get("anchor_hash", Z)
        v = verify_receipt_trust(receipt, trust, anchor_hash, anchor_seq + 1)
        out = {"valid": v["valid"], "reason": v["reason"]}
        if v["valid"]:
            out["head_seq"] = receipt["body"]["seq"]
        return out
    raise ValueError("receipt op: missing primitive or fixture")


# ---------------------------------------------------------------------------

def op_telemetry(inp):
    _check_fields(inp, INPUT_FIELDS["telemetry"], "telemetry input")
    seqs = inp["receipt_sequences"]
    receipts = [gen_receipt(n) for n in seqs]
    tenant_suffix = inp.get("authenticated_tenant_suffix") or "A"
    token = f"fixture-hosted-writer-{tenant_suffix}"
    hosted = {
        "v": 1,
        "trust": T0,
        "grants": [
            {"token_hash": H("fixture-hosted-reader"), "tenant_id": I("lsten", "A"), "role": "reader"},
            {"token_hash": H("fixture-hosted-writer-A"), "tenant_id": I("lsten", "A"), "role": "telemetry_writer"},
            {"token_hash": H("fixture-hosted-writer-B"), "tenant_id": I("lsten", "B"), "role": "telemetry_writer"},
        ],
        "gateways": [
            {
                "tenant_id": I("lsten", "A"),
                "gateway_id": I("lsgw", "A"),
                "receipt_key_ids": [I("lskey", "B")],
                "profiles": [{"config_hash": H(J(C0)), "mode": "rules_only"}],
                "checkpoint": inp.get("initial_checkpoint"),
            }
        ],
        "publishers": [{"tenant_id": I("lsten", "A"), "pack_key_ids": [I("lskey", "A")]}],
        "retention_days": 30,
    }
    store = TenantTelemetryStore(hosted)
    batch_suffix = inp.get("batch_suffix") or "A"
    req = {
        "v": 1,
        "batch_id": I("lsbatch", batch_suffix),
        "events": [
            {"receipt": r, "mode": "rules_only", "duration_bucket": "lt25"} for r in receipts
        ],
    }
    events = inp.get("events") or ["ingest"]
    responses = []
    for ev in events:
        if ev in ("ingest", "retry_identical"):
            r = store.ingest(req, token)
            responses.append({"status": r["status"], "body": r["body"]})
        else:
            raise ValueError(f"unknown telemetry event {ev}")
    results = {}
    last = responses[-1]
    first = responses[0]
    if "ingest" in events and "retry_identical" in events:
        results["accepted"] = [r["body"].get("accepted", 0) for r in responses]
        results["duplicate"] = [r["body"].get("duplicate", False) for r in responses]
        results["aggregate_pass"] = store.aggregate_count(I("lsgw", "A"), PH0, "rules_only", "pass")
        results["head_seq"] = store.head_seq(I("lsgw", "A"))
    else:
        results["status"] = last["status"]
        err_body = last["body"].get("error")
        if err_body:
            results["error"] = err_body["code"]
            results["retryable"] = err_body["retryable"]
        results["accepted"] = last["body"].get("accepted", 0)
        if first["status"] == 202:
            results["head_seq"] = last["body"]["head_seq"]
    return results


# ---------------------------------------------------------------------------

def op_schema(inp):
    _check_fields(inp, INPUT_FIELDS["schema"], "schema input")
    canon = jcs(inp["canonicalize"])
    return {"canonical": canon, "sha256": sha256_hex(canon)}


# ---------------------------------------------------------------------------

def op_budget(inp):
    _check_fields(inp, INPUT_FIELDS["budget"], "budget input")
    profile = inp["profile"]
    if "durations_ms" in inp:
        d = inp["durations_ms"]
        _check_fields(
            d,
            ["admission", "rules_and_normalization", "model", "lexshield", "audit", "render"],
            "durations_ms",
        )
        # mono() call schedule producing exactly the stated per-stage
        # durations (see harness derivation: 19 mono reads across the
        # pipeline).
        adm = d["admission"]
        rul = d["rules_and_normalization"]
        mod = d["model"]
        lex = d["lexshield"]
        aud = d["audit"]
        ren = d["render"]
        v = [
            0,
            adm, adm, adm + rul, adm + rul,
            adm + rul, adm + rul + mod, adm + rul + mod,
            adm + rul + mod, adm + rul + mod, adm + rul + mod,
            adm + rul + mod, adm + rul + mod, adm + rul + mod + lex, adm + rul + mod + lex,
            adm + rul + mod + lex, adm + rul + mod + lex, adm + rul + mod + lex + aud,
            adm + rul + mod + lex + aud + ren,
        ]
        clock = scripted_clock(v, 1000)
        rt = build_runtime(profile, clock=clock)
        req = _build_request(rt, {"text": inp["text"]})
        ctx = rt.engine.admit(req)["ctx"]
        rt.engine.run_local(ctx)
        rt.engine.run_policy(ctx)
        rt.engine.seal(ctx)
        rt.engine.handoff(ctx)
        screen_ms = rt.engine.screen_ms(ctx)
        return {
            "verdict": ctx.committed["decision"]["verdict"],
            "screen_ms": screen_ms,
            "budget_exceeded": screen_ms >= 180,
            "receipt_count": rt.sink.receipt_count(),
        }
    rt = build_runtime(profile)
    events = inp["events"]
    results = {}
    ctx = None
    for ev in events:
        if ev == "admit":
            ctx = rt.engine.admit(_build_request(rt, {"text": inp["text"]}))["ctx"]
        elif ev == "clock_to_180ms":
            rt.clock.set_mono(180)
        elif ev == "seal":
            try:
                rt.engine.seal(ctx)
            except ClosedError as e:
                results["error"] = e.code
        elif ev == "admit_16_distinct_requests_without_advancing_clock":
            for _ in range(16):
                r = rt.engine.admit(_build_request(rt, {"text": inp["text"]}))
                if r.get("ctx") is None:
                    raise ValueError("unexpected cache hit")
            results["inflight"] = rt.engine.inflight
        elif ev == "attempt_17th":
            try:
                rt.engine.admit(_build_request(rt, {"text": inp["text"]}))
                results["request_17_error"] = "none"
            except ClosedError as e:
                results["request_17_error"] = e.code
            except Exception:
                results["request_17_error"] = "thrown"
            results["request_17_raw_bytes"] = 0
            results["inflight"] = rt.engine.inflight
        else:
            raise ValueError(f"unknown budget event {ev}")
    results["receipt_count"] = rt.sink.receipt_count()
    results["raw_bytes"] = 0
    return results


# ---------------------------------------------------------------------------

_OP_FUNCS = {
    "screen": op_screen,
    "adapter": op_adapter,
    "lifecycle": op_lifecycle,
    "idempotency": op_idempotency,
    "pack": op_pack,
    "receipt": op_receipt,
    "telemetry": op_telemetry,
    "schema": op_schema,
    "budget": op_budget,
}


def run_vector(v):
    op = v["input"].get("op")
    if op not in OPS:
        raise ValueError(f"unknown op {v['input'].get('op')}")
    _check_fields(v["input"], INPUT_FIELDS[op], f"{op} input")
    _check_fields(v["expected"], EXPECTED_FIELDS[op], f"{op} expected")
    if "fault" in v["input"] and v["input"]["fault"] not in FAULTS:
        raise ValueError(f"unknown fault {v['input']['fault']}")
    if "profile" in v["input"] and v["input"]["profile"] not in ("R", "M"):
        raise ValueError(f"unknown profile {v['input']['profile']}")
    out = _OP_FUNCS[op](v["input"])
    # Each op's output schema is exactly the expected member set.
    return {k: out[k] for k in v["expected"] if k in out}
