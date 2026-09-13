"""The LexSieve engine: the mandatory return-path interceptor. screen() is
the sole model-delivery entry point. Phases are exposed individually so the
conformance harness and hosts can interpose the section 9.1 lifecycle
events (admit / rules / model / transform / policy / sealing / committed /
handed_off / done / discarded).
"""

import math
import time

from .crypto import sha256_hex
from .errors import ClosedError
from .jcs import jcs
from .lexshield import STATIC_POLICY_HASH  # noqa: F401  (re-export parity)
from .model import MODEL_CLASSES, featurize, model_hash, score as model_score
from .normalize import HoldSignal, build_views
from .packs import config_hash_of  # noqa: F401  (re-export parity)
from .receipts import sign_receipt
from .rules import (
    CLASS_ORDER,
    FINDING_CAP,
    compile_baseline,
    compile_pack_rules,
    dedup_sort_findings,
    encoding_findings,
    match_rule_in_view,
)
from .schema import validate_screen_request


class SystemClock:
    """wall = Unix ms (trusted host clock); mono = monotonic ms."""

    def now(self):
        return int(time.time() * 1000)

    def mono(self):
        return time.monotonic() * 1000


SYSTEM_CLOCK = SystemClock()

# Stage budgets in ms (spec 6.5). A budget is exhausted at elapsed >= bound.
BUDGET = {
    "admission": 10,
    "rules": 35,  # normalization/rules/closure
    "model": 80,
    "lexshield": 15,
    "audit": 20,
    "render": 5,
    "reserve": 15,
    "hard": 180,
}

REMOVED = "[lexsieve:removed]"
HOLD_NOTICE = "Tool result withheld by LexSieve."
STRIP_NOTICE = "Suspect spans removed."


class Ctx:
    """Screening context. Attribute names mirror the TS Ctx fields."""

    def __init__(self, req, input_hash, binding_hash, snapshot, decision_id,
                 receipt_id, t0):
        self.req = req
        self.candidate = req["candidate"]
        self.input_hash = input_hash
        self.binding_hash = binding_hash
        self.snapshot = snapshot
        self.decision_id = decision_id
        self.receipt_id = receipt_id
        self.t0 = t0
        self.findings = []
        self.replacements = []
        self.verdict = "pass"
        self.reason = None
        self.hold_reason = None
        self.data = []
        self.quarantine_id = None
        self.policy_result = None
        self.reduced_coverage = False
        self.stage_ms = {
            "admission": 0, "rules": 0, "model": 0, "lexshield": 0, "audit": 0, "render": 0,
        }
        self.state = "admitted"
        self.committed = None
        self.cached_result = False
        self.model_elapsed = 0
        self.model_positive = []


class Engine:
    def __init__(self, config, deps):
        self.config = config
        self.deps = deps
        active = deps["sink"].get_active_snapshot(config["tenant_id"], config["gateway_id"])
        if not active:
            raise ClosedError("NOT_READY", "no active snapshot")
        self.active = active
        stored_pack = deps["sink"].get_pack(
            config["tenant_id"], active["pack_id"], active["pack_serial"]
        )
        if not stored_pack:
            raise ClosedError("NOT_READY", "active pack missing")
        self.pack = stored_pack["pack"]
        self.rules = compile_baseline() + compile_pack_rules(self.pack["body"]["rules"])
        if config["mode"] == "required":
            self.artifact = self.pack["body"]["model"]
            self.artifact_hash = model_hash(self.artifact) if self.artifact else None
            if active["snapshot"]["model_hash"] != self.artifact_hash:
                raise ClosedError("NOT_READY", "model hash mismatch")
        else:
            self.artifact = None
            self.artifact_hash = None
        self.inflight = 0
        # fault hooks (conformance harness only; production leaves them unset)
        self.model_port = None
        self.mode_override = None

    # -- injected pieces -----------------------------------------------------

    def _mono(self):
        return self.deps["clock"].mono()

    def _now(self):
        return self.deps["clock"].now()

    # -- admission ------------------------------------------------------------

    def admit(self, request_json):
        """Validates the request, applies idempotency, readiness, and
        capacity, pins the active snapshot, reserves decision/receipt IDs.
        Returns {"ctx": Ctx} for a new screening, or {"cached":
        ScreenResponse} for an idempotent retry."""
        req = validate_screen_request(request_json)
        cand = req["candidate"]
        input_hash = sha256_hex(jcs(cand))
        binding_hash = sha256_hex(jcs(cand["binding"]))
        sink = self.deps["sink"]

        existing = sink.get_decision(
            cand["binding"]["tenant_id"], cand["binding"]["gateway_id"], cand["result_id"]
        )
        if existing:
            if existing["input_hash"] != input_hash or existing["binding_hash"] != binding_hash:
                raise ClosedError("CONFLICT", "result id reused with different input")
            # equal input: cached path requires the pinned snapshot to still be active
            if not self._snapshot_active(existing["epoch"]):
                raise ClosedError("STALE_POLICY", "pinned snapshot no longer active")
            receipt = sink.get_receipt_by_id(existing["receipt_id"])
            if not receipt:
                raise ClosedError("STORAGE_UNAVAILABLE", "decision without receipt")
            envelope = self._reconstruct_envelope(existing["decision"], cand, receipt)
            return {
                "cached": {
                    "v": 1,
                    "decision": existing["decision"],
                    "envelope": envelope,
                    "receipt": receipt,
                    "cached": True,
                }
            }
        by_binding = sink.get_decision_by_binding(
            cand["binding"]["tenant_id"], cand["binding"]["gateway_id"], binding_hash
        )
        if by_binding:
            raise ClosedError("CONFLICT", "invocation slot reused")

        # readiness: active snapshot usable
        if not self._snapshot_active(self.active["epoch"]):
            raise ClosedError("NOT_READY", "no active unexpired policy")
        if (
            cand["binding"]["tenant_id"] != self.config["tenant_id"]
            or cand["binding"]["gateway_id"] != self.config["gateway_id"]
        ):
            raise ClosedError("FORBIDDEN", "binding outside configured tenant/gateway")
        if self.inflight >= self.config["max_inflight"]:
            raise ClosedError("RATE_LIMITED", "admission cap")

        self.inflight += 1
        ctx = Ctx(
            req,
            input_hash,
            binding_hash,
            self.active["snapshot"],
            self.deps["ids"].next("lsdec"),
            self.deps["ids"].next("lsrcp"),
            self._mono(),
        )
        return {"ctx": ctx}

    def _snapshot_active(self, epoch):
        a = self.deps["sink"].get_active_snapshot(
            self.config["tenant_id"], self.config["gateway_id"]
        )
        if not a or a["epoch"] != epoch:
            return False
        if self._now() >= a["pack_expires_at_ms"]:
            return False
        return True

    def _refresh_active(self):
        a = self.deps["sink"].get_active_snapshot(
            self.config["tenant_id"], self.config["gateway_id"]
        )
        if a:
            self.active = a

    def _deadline_exceeded(self, ctx):
        return self._mono() - ctx.t0 >= BUDGET["hard"]

    def _check_deadline(self, ctx):
        if self._deadline_exceeded(ctx):
            self.discard(ctx)
            raise ClosedError("DEADLINE", "hard deadline")

    # -- local stages: rules -> model -> transform -----------------------------

    def run_local(self, ctx):
        if ctx.state != "admitted":
            raise ClosedError("INTERNAL", "bad state")
        s0 = self._mono()
        self._check_deadline(ctx)
        ctx.state = "rules"
        block_lens = [len(b["text"].encode("utf-8")) for b in ctx.candidate["blocks"]]
        views = None
        try:
            views = build_views(ctx.candidate["blocks"])
            findings = []
            for view in views.rule_views:
                for rule in self.rules:
                    for alt in rule["alternatives"]:
                        for sp in match_rule_in_view(view, alt, block_lens):
                            findings.append(
                                {"rule_id": rule["id"], "class": rule["cls"], "span": sp}
                            )
            for inp in views.predicate_inputs:
                for hit in encoding_findings(inp, block_lens):
                    findings.append(
                        {"rule_id": "builtin.encoding", "class": "encoding", "span": hit}
                    )
            ctx.findings = dedup_sort_findings(findings)
        except HoldSignal as e:
            ctx.hold_reason = e.reason
            ctx.verdict = "hold"
            ctx.reason = e.reason
        ctx.stage_ms["rules"] += self._mono() - s0
        self._check_deadline(ctx)

        # finding cap
        if ctx.hold_reason is None and len(ctx.findings) > FINDING_CAP:
            ctx.findings = ctx.findings[:FINDING_CAP]
            self._propose_hold(ctx, "FINDING_LIMIT")
        if ctx.hold_reason is None and any(
            self._action_of(f["rule_id"]) == "hold" for f in ctx.findings
        ):
            self._propose_hold(ctx, "RULE_BLOCK")

        # model stage
        mode = self.mode_override or self.config["mode"]
        if ctx.hold_reason is None and mode == "required":
            ctx.state = "model"
            m0 = self._mono()
            self._run_model(ctx, views)
            ctx.model_elapsed = self._mono() - m0
            ctx.stage_ms["model"] += ctx.model_elapsed
            # A completed positive result stands only when it arrived inside
            # the model budget; a valid response at/after 80 ms is a timeout.
            if (
                ctx.hold_reason is None
                and len(ctx.model_positive) > 0
                and ctx.model_elapsed < BUDGET["model"]
            ):
                for c in ctx.model_positive:
                    ctx.findings.append({"rule_id": f"model.{c}", "class": c, "span": None})
                ctx.findings = dedup_sort_findings(ctx.findings)
                self._propose_hold(ctx, "MODEL_BLOCK")
            elif ctx.hold_reason is None and ctx.model_elapsed >= BUDGET["model"]:
                self._propose_hold(ctx, "MODEL_TIMEOUT")
            self._check_deadline(ctx)
        elif ctx.hold_reason is None and mode == "rules_only":
            ctx.reduced_coverage = True

        # transform stage
        ctx.state = "transform"
        t0 = self._mono()
        self._run_transform(ctx, block_lens)
        ctx.stage_ms["rules"] += self._mono() - t0
        self._check_deadline(ctx)
        ctx.state = "policy"

    def _action_of(self, rule_id):
        r = next((x for x in self.rules if x["id"] == rule_id), None)
        return r["action"] if r else "hold"

    def _propose_hold(self, ctx, reason):
        if ctx.hold_reason is None:
            ctx.hold_reason = reason
            ctx.verdict = "hold"
            ctx.reason = reason

    def _run_model(self, ctx, views):
        if self.artifact is None or self.artifact_hash is None:
            self._propose_hold(ctx, "MODEL_REQUIRED")
            return
        try:
            rv = views if views is not None else build_views(ctx.candidate["blocks"])
            feature_set = featurize(rv.rule_views)
            if len(feature_set) > 32768:
                self._propose_hold(ctx, "LIMIT")
                return
            features = sorted(feature_set, key=lambda s: s.encode("utf-8"))
        except HoldSignal as e:
            self._propose_hold(ctx, e.reason)
            return
        port = self.model_port or (
            lambda req: model_score(self.artifact, req["features"])
        )
        try:
            resp = port({"v": 1, "model_hash": self.artifact_hash, "features": features})
        except ClosedError as e:
            if e.code == "NOT_FOUND":
                self._propose_hold(ctx, "MODEL_REQUIRED")
            else:
                self._propose_hold(ctx, "MODEL_INVALID")
            return
        except Exception:
            self._propose_hold(ctx, "MODEL_INVALID")
            return
        # validate response: exact schema + pinned hash + arithmetic agreement
        invalid = False
        try:
            if sorted(resp.keys()) != ["model_hash", "positive", "scores", "v"]:
                invalid = True
            if (
                resp.get("v") != 1
                or resp.get("model_hash") != self.artifact_hash
                or not isinstance(resp.get("scores"), list)
                or len(resp["scores"]) != 3
                or not all(
                    isinstance(s, int) and not isinstance(s, bool) for s in resp["scores"]
                )
                or not isinstance(resp.get("positive"), list)
                or not all(c in MODEL_CLASSES for c in resp["positive"])
                or len(set(resp["positive"])) != len(resp["positive"])
            ):
                invalid = True
            expected = model_score(self.artifact, features)
            if not invalid and (
                resp["scores"] != expected["scores"] or resp["positive"] != expected["positive"]
            ):
                invalid = True
        except Exception:
            invalid = True
        if invalid:
            self._propose_hold(ctx, "MODEL_INVALID")
            return
        ctx.model_positive = list(resp["positive"])

    # Transform: merge strip spans, apply replacements, closure pass.
    def _run_transform(self, ctx, block_lens):
        if ctx.hold_reason is not None:
            ctx.data = []
            ctx.replacements = []
            return
        strip_spans = [
            f["span"]
            for f in ctx.findings
            if self._action_of(f["rule_id"]) == "strip" and f["span"] is not None
        ]
        if not strip_spans:
            ctx.data = ctx.candidate["blocks"]
            ctx.verdict = "pass"
            return
        # union overlapping/adjacent spans per block
        merged = merge_spans(strip_spans)
        if len(merged) > 64:
            self._propose_hold(ctx, "FINDING_LIMIT")
            ctx.data = []
            ctx.replacements = []
            return
        ctx.replacements = merged
        new_blocks, marker_ranges = apply_replacements(ctx.candidate["blocks"], merged)
        # closure pass: rescan transformed text with rules (+ required model)
        closure_findings = self._closure_scan(ctx, new_blocks, marker_ranges, block_lens)
        if closure_findings:
            ctx.findings = dedup_sort_findings(ctx.findings + closure_findings)
            model_hit = any(f["rule_id"].startswith("model.") for f in closure_findings)
            self._propose_hold(ctx, "MODEL_BLOCK" if model_hit else "RULE_BLOCK")
            ctx.data = []
            ctx.replacements = []
            ctx.verdict = "hold"
            return
        ctx.data = new_blocks
        ctx.verdict = "strip"
        ctx.reason = "STRIPPED"

    # Rescans transformed text. Findings touching inserted marker bytes
    # become whole-result findings; others map back to original-byte spans.
    def _closure_scan(self, ctx, blocks, marker_ranges, orig_block_lens):
        out = []
        new_lens = [len(b["text"].encode("utf-8")) for b in blocks]
        try:
            views = build_views(blocks)
        except HoldSignal:
            # resource failure during closure -> whole-result LIMIT hold
            out.append({"rule_id": "builtin.encoding", "class": "encoding", "span": None})
            return out

        def map_span(sp):
            # new-text span -> original coords; marker intersection -> None
            for ms, me in marker_ranges.get(sp["block"], []):
                if sp["start"] < me and sp["end"] > ms:
                    return None
            reps = sorted(
                [r for r in ctx.replacements if r["block"] == sp["block"]],
                key=lambda r: r["start"],
            )
            marks = marker_ranges.get(sp["block"], [])
            start = _map_new_to_orig(sp["start"], reps, marks)
            end = _map_new_to_orig(sp["end"] - 1, reps, marks) + 1
            limit = orig_block_lens[sp["block"]] if sp["block"] < len(orig_block_lens) else 0
            if start < 0 or end < 0 or end > limit:
                return None
            return {"block": sp["block"], "start": start, "end": end}

        for view in views.rule_views:
            for rule in self.rules:
                for alt in rule["alternatives"]:
                    for sp in match_rule_in_view(view, alt, new_lens):
                        out.append(
                            {"rule_id": rule["id"], "class": rule["cls"], "span": map_span(sp)}
                        )
        for inp in views.predicate_inputs:
            for hit in encoding_findings(inp, new_lens):
                out.append(
                    {"rule_id": "builtin.encoding", "class": "encoding", "span": map_span(hit)}
                )
        mode = self.mode_override or self.config["mode"]
        if mode == "required" and self.artifact:
            try:
                feature_set = featurize(views.rule_views)
                if len(feature_set) <= 32768:
                    features = sorted(feature_set, key=lambda s: s.encode("utf-8"))
                    resp = model_score(self.artifact, features)
                    for c in resp["positive"]:
                        out.append({"rule_id": f"model.{c}", "class": c, "span": None})
            except Exception:
                # a closure model failure surfaces as MODEL_INVALID upstream
                out.append({"rule_id": "model.override", "class": "override", "span": None})
        return out

    # -- policy ---------------------------------------------------------------

    def run_policy(self, ctx):
        if ctx.state != "policy":
            raise ClosedError("INTERNAL", "bad state")
        self._check_deadline(ctx)
        s0 = self._mono()
        classes = _unique_classes(ctx.findings)
        req = {
            "v": 1,
            "request_id": ctx.req["request_id"],
            "binding": ctx.candidate["binding"],
            "input_hash": ctx.input_hash,
            "snapshot": ctx.snapshot,
            "candidate_verdict": ctx.verdict,
            "classes": classes,
        }
        resp = None
        try:
            r = self.deps["lexshield"].evaluate_return(req)
            if (
                r
                and r.get("v") == 1
                and r.get("policy_hash") == self.deps["lexshield"].policy_hash
            ):
                resp = r
        except Exception:
            resp = None
        ctx.stage_ms["lexshield"] = self._mono() - s0
        if ctx.stage_ms["lexshield"] >= BUDGET["lexshield"]:
            resp = None
        if resp is None:
            self._propose_hold(ctx, "LEXSHIELD_TIMEOUT")
        elif resp["disposition"] == "block":
            self._propose_hold(ctx, "LEXSHIELD_BLOCK")
        ctx.policy_result = resp
        ctx.state = "sealing"
        self._check_deadline(ctx)

    # -- sealing / commit ------------------------------------------------------

    def seal(self, ctx):
        if ctx.state != "sealing":
            # allow 'seal' event to run remaining local stages first
            if ctx.state == "admitted":
                self.run_local(ctx)
            if ctx.state == "policy":
                self.run_policy(ctx)
        if ctx.state != "sealing":
            raise ClosedError("INTERNAL", "bad state")
        self._refresh_active()
        if self.active["epoch"] != ctx.snapshot["epoch"]:
            self._propose_hold(ctx, "POLICY_CHANGED")
        elif self._now() >= self.active["pack_expires_at_ms"]:
            self._propose_hold(ctx, "PACK_EXPIRED")
        self._check_deadline(ctx)
        s0 = self._mono()

        if ctx.verdict == "hold":
            ctx.data = []
            ctx.replacements = []
            ctx.quarantine_id = self.deps["ids"].next("lsq")
        notice = (
            None
            if ctx.verdict == "pass"
            else (STRIP_NOTICE if ctx.verdict == "strip" else HOLD_NOTICE)
        )
        envelope = {
            "type": "lexsieve.tool-data.v1",
            "result_id": ctx.candidate["result_id"],
            "decision_id": ctx.decision_id,
            "receipt_id": ctx.receipt_id,
            "trust": "untrusted",
            "disposition": ctx.verdict,
            "provenance": {
                "tool": ctx.candidate["binding"]["tool"],
                "adapter": ctx.candidate["binding"]["adapter"],
                "content_sha256": sha256_hex(jcs(ctx.candidate["blocks"])),
            },
            "notice": notice,
            "data": ctx.data,
        }
        decision = {
            "decision_id": ctx.decision_id,
            "result_id": ctx.candidate["result_id"],
            "input_hash": ctx.input_hash,
            "snapshot": ctx.snapshot,
            "policy_result": ctx.policy_result,
            "verdict": ctx.verdict,
            "reason": ctx.reason or "CLEAN",
            "findings": dedup_sort_findings(ctx.findings)[:FINDING_CAP],
            "replacements": sorted(ctx.replacements, key=_span_key),
            "output_hash": sha256_hex(jcs(envelope)),
            "quarantine_id": ctx.quarantine_id,
        }
        signer = self.deps["signer"]
        recorded_at = self._now()

        def build(seq, prev_hash):
            body = {
                "v": 1,
                "receipt_id": ctx.receipt_id,
                "tenant_id": ctx.candidate["binding"]["tenant_id"],
                "gateway_id": ctx.candidate["binding"]["gateway_id"],
                "seq": seq,
                "recorded_at_ms": recorded_at,
                "prev_hash": prev_hash,
                "decision": decision,
            }
            signed = sign_receipt(body, signer["seed"])
            receipt = {
                "body": body,
                "hash": signed["hash"],
                "key_id": signer["key_id"],
                "signature": signed["signature"],
            }
            quarantine = (
                {
                    "v": 1,
                    "type": "lexsieve.quarantine.v1",
                    "content_kind": (
                        "suspected_instruction" if decision["findings"] else "unclassified"
                    ),
                    "quarantine_id": ctx.quarantine_id,
                    "result_id": ctx.candidate["result_id"],
                    "receipt_id": ctx.receipt_id,
                    "expires_at_ms": recorded_at + self.config["retention_days"] * 86400000,
                }
                if ctx.verdict == "hold"
                else None
            )
            return {"receipt": receipt, "decision": decision, "quarantine": quarantine}

        res = self.deps["sink"].commit(
            ctx.candidate["binding"]["tenant_id"],
            ctx.candidate["binding"]["gateway_id"],
            ctx.candidate["result_id"],
            ctx.input_hash,
            ctx.binding_hash,
            ctx.snapshot["epoch"],
            build,
        )
        if res["status"] in ("exists", "binding_conflict"):
            # a racing commit won; adopt its decision through the cached path
            stored = res["stored"]
            if (
                stored["input_hash"] != ctx.input_hash
                or stored["binding_hash"] != ctx.binding_hash
            ):
                self.discard(ctx)
                raise ClosedError("CONFLICT", "racing commit conflict")
            receipt = self.deps["sink"].get_receipt_by_id(stored["receipt_id"])
            if not receipt:
                raise ClosedError("STORAGE_UNAVAILABLE", "decision without receipt")
            envelope2 = self._reconstruct_envelope(stored["decision"], ctx.candidate, receipt)
            ctx.committed = {
                "decision": stored["decision"],
                "envelope": envelope2,
                "receipt": receipt,
            }
            ctx.cached_result = True
            ctx.state = "committed"
            ctx.stage_ms["audit"] = self._mono() - s0
            return
        ctx.committed = {"decision": decision, "envelope": envelope, "receipt": res["receipt"]}
        ctx.state = "committed"
        ctx.stage_ms["audit"] = self._mono() - s0

    # -- handoff ---------------------------------------------------------------

    def handoff(self, ctx):
        if ctx.state != "committed" and ctx.state in ("admitted", "policy"):
            self.seal(ctx)
        if not ctx.committed:
            raise ClosedError("INTERNAL", "no committed decision")
        self._refresh_active()
        stale = (
            self.active["epoch"] != ctx.snapshot["epoch"]
            or self._now() >= self.active["pack_expires_at_ms"]
        )
        if stale:
            self.discard(ctx)
            raise ClosedError("STALE_POLICY", "epoch/expiry before handoff")
        ctx.state = "handed_off"
        e = ctx.committed["envelope"]
        ctx.state = "done"
        self.inflight -= 1
        return e

    # Full screen(): admit -> local -> policy -> seal -> handoff.
    def screen(self, request_json):
        r = self.admit(request_json)
        ctx = r.get("ctx")
        if "cached" in r and r["cached"] is not None:
            return r["cached"]
        try:
            self.run_local(ctx)
            self.run_policy(ctx)
            self.seal(ctx)
            self.handoff(ctx)
        except Exception:
            if ctx.state not in ("committed", "done", "discarded"):
                self.discard(ctx)
            raise
        return {
            "v": 1,
            "decision": ctx.committed["decision"],
            "envelope": ctx.committed["envelope"],
            "receipt": ctx.committed["receipt"],
            "cached": ctx.cached_result,
        }

    def discard(self, ctx):
        if ctx.state not in ("done", "discarded"):
            ctx.state = "discarded"
            self.inflight = max(0, self.inflight - 1)

    def _reconstruct_envelope(self, decision, cand, receipt):
        data = []
        if decision["verdict"] == "pass":
            data = cand["blocks"]
        elif decision["verdict"] == "strip":
            data = apply_replacements(cand["blocks"], decision["replacements"])[0]
        notice = (
            None
            if decision["verdict"] == "pass"
            else (STRIP_NOTICE if decision["verdict"] == "strip" else HOLD_NOTICE)
        )
        return {
            "type": "lexsieve.tool-data.v1",
            "result_id": cand["result_id"],
            "decision_id": decision["decision_id"],
            "receipt_id": receipt["body"]["receipt_id"],
            "trust": "untrusted",
            "disposition": decision["verdict"],
            "provenance": {
                "tool": cand["binding"]["tool"],
                "adapter": cand["binding"]["adapter"],
                "content_sha256": sha256_hex(jcs(cand["blocks"])),
            },
            "notice": notice,
            "data": data,
        }

    def screen_ms(self, ctx):
        return math.floor(self._mono() - ctx.t0 + 0.5)

    def bare_ctx(self, req, snapshot):
        """Replay support: build a side-effect-free context pinned to a
        recorded snapshot. No idempotency check, no inflight accounting, no
        ID allocation beyond reusing the recorded ones."""
        cand = req["candidate"]
        ctx = Ctx(
            req,
            sha256_hex(jcs(cand)),
            sha256_hex(jcs(cand["binding"])),
            snapshot,
            "lsdec_000000000000000000000",
            "lsrcp_000000000000000000000",
            self._mono(),
        )
        return ctx


# ---------------------------------------------------------------------------

def _span_key(s):
    return (s["block"], s["start"], s["end"])


def merge_spans(spans):
    by_block = {}
    for s in spans:
        by_block.setdefault(s["block"], []).append((s["start"], s["end"]))
    out = []
    for block, arr in by_block.items():
        arr.sort(key=lambda x: x[0])
        cs, ce = arr[0]
        for s, e in arr[1:]:
            if s <= ce:
                ce = max(ce, e)
            else:
                out.append({"block": block, "start": cs, "end": ce})
                cs, ce = s, e
        out.append({"block": block, "start": cs, "end": ce})
    out.sort(key=_span_key)
    return out


def apply_replacements(blocks, replacements):
    """Applies replacements to blocks, returning (new_blocks, marker_ranges)
    where marker_ranges maps block index -> byte ranges (in new-text
    coordinates) occupied by inserted markers."""
    marker_ranges = {}
    out = []
    removed_b = REMOVED.encode("utf-8")
    for b in blocks:
        reps = sorted(
            [r for r in replacements if r["block"] == b["index"]],
            key=lambda r: -r["start"],
        )
        # work on UTF-8 bytes
        buf = b["text"].encode("utf-8")
        applied = []
        for r in reps:
            buf = buf[: r["start"]] + removed_b + buf[r["end"] :]
            applied.append({"start": r["start"], "end": r["start"] + len(REMOVED)})
        # applied is in descending order; normalize to ascending marker ranges
        applied.sort(key=lambda a: a["start"])
        marks = [(a["start"], a["end"]) for a in applied]
        if marks:
            marker_ranges[b["index"]] = marks
        out.append({"index": b["index"], "text": buf.decode("utf-8")})
    return out, marker_ranges


def _map_new_to_orig(off, reps, marks):
    """Maps a byte offset in transformed text back to original coordinates
    using the sorted replacements and marker ranges of that block."""
    delta = 0
    marker_len = len(REMOVED)
    for r in reps:
        new_start = r["start"] - delta
        removed_len = r["end"] - r["start"]
        if off < new_start:
            break
        if off < new_start + marker_len:
            return -1  # inside marker
        delta += removed_len - marker_len
    return off + delta


def _unique_classes(findings):
    present = {f["class"] for f in findings}
    return [c for c in CLASS_ORDER if c in present]
