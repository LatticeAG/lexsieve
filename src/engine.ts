// The LexSieve engine: the mandatory return-path interceptor. screen() is the
// sole model-delivery entry point. Phases are exposed individually so the
// conformance harness and hosts can interpose the section 9.1 lifecycle
// events (admit / rules / model / transform / policy / sealing / committed /
// handed_off / done / discarded).

import { ClosedError } from './errors.ts';
import { sha256Hex } from './crypto.ts';
import { jcs, type JsonValue } from './jcs.ts';
import type { IdAllocator } from './ids.ts';
import type { LexShieldPort } from './lexshield.ts';
import { featurize, score as modelScore, modelHash, MODEL_CLASSES, type ModelArtifact, type ModelResponse } from './model.ts';
import { buildViews, HoldSignal, acharText } from './normalize.ts';
import { packHash } from './receipts.ts';
import { receiptHash, signReceipt } from './receipts.ts';
import {
  compileBaseline,
  compilePackRules,
  dedupSortFindings,
  encodingFindings,
  matchRuleInView,
  CLASS_ORDER,
  FINDING_CAP,
  type Class,
  type Finding,
  type Rule,
} from './rules.ts';
import {
  validateScreenRequest,
  type Candidate,
  type DataEnvelope,
  type Decision,
  type PolicyResponse,
  type QuarantineMetadata,
  type Reason,
  type ReceiptBody,
  type ScreenRequest,
  type ScreenResponse,
  type SignedPack,
  type Snapshot,
  type Span,
  type TextBlock,
  type Verdict,
} from './schema.ts';
import type { ActiveSnapshotRecord, Sink } from './sink.ts';
import { configHashOf } from './packs.ts';

export interface Clock {
  now(): number; // wall clock, Unix ms (trusted host clock)
  mono(): number; // monotonic ms
}

export const SYSTEM_CLOCK: Clock = {
  now: () => Date.now(),
  mono: () => performance.now(),
};

// Stage budgets in ms (spec 6.5). A budget is exhausted at elapsed >= bound.
export const BUDGET = {
  admission: 10,
  rules: 35, // normalization/rules/closure
  model: 80,
  lexshield: 15,
  audit: 20,
  render: 5,
  reserve: 15,
  hard: 180,
} as const;

export interface ModelPort {
  (req: { v: 1; model_hash: string; features: string[] }): ModelResponse;
}

export interface EngineDeps {
  sink: Sink;
  clock: Clock;
  ids: IdAllocator;
  lexshield: LexShieldPort;
  signer: { keyId: string; seed: Uint8Array };
}

export type ProposedHold =
  | 'RULE_BLOCK' | 'MODEL_BLOCK' | 'MODEL_REQUIRED' | 'MODEL_TIMEOUT' | 'MODEL_INVALID'
  | 'LEXSHIELD_BLOCK' | 'LEXSHIELD_TIMEOUT' | 'FINDING_LIMIT' | 'LIMIT' | 'INVALID_UTF8'
  | 'POLICY_CHANGED' | 'PACK_EXPIRED' | 'DEADLINE';

export interface Ctx {
  req: ScreenRequest;
  candidate: Candidate;
  inputHash: string;
  bindingHash: string;
  snapshot: Snapshot;
  decisionId: string;
  receiptId: string;
  t0: number;
  // results
  findings: Finding[];
  replacements: Span[];
  verdict: Verdict;
  reason: Reason | null;
  holdReason: ProposedHold | null;
  data: TextBlock[];
  quarantineId: string | null;
  policyResult: PolicyResponse | null;
  reducedCoverage: boolean;
  stageMs: Record<'admission' | 'rules' | 'model' | 'lexshield' | 'audit' | 'render', number>;
  state: 'admitted' | 'rules' | 'model' | 'transform' | 'policy' | 'sealing' | 'committed' | 'handed_off' | 'done' | 'discarded';
  committed: { decision: Decision; envelope: DataEnvelope; receipt: import('./schema.ts').SignedReceipt } | null;
  cachedResult: boolean;
  modelElapsed: number;
  modelPositive: Class[];
}

const REMOVED = '[lexsieve:removed]';
const HOLD_NOTICE = 'Tool result withheld by LexSieve.';
const STRIP_NOTICE = 'Suspect spans removed.';

export class Engine {
  rules: Rule[]; // baseline + pack extra rules (compiled)
  artifact: ModelArtifact | null;
  artifactHash: string | null;
  active: ActiveSnapshotRecord;
  pack: SignedPack;
  inflight = 0;
  // fault hooks (conformance harness only; production leaves them unset)
  modelPort: ModelPort | null = null;
  modeOverride: 'required' | 'rules_only' | null = null;

  readonly config: import('./schema.ts').Config;
  readonly deps: EngineDeps;

  constructor(config: import('./schema.ts').Config, deps: EngineDeps) {
    this.config = config;
    this.deps = deps;
    const active = deps.sink.getActiveSnapshot(config.tenant_id, config.gateway_id);
    if (!active) throw new ClosedError('NOT_READY', 'no active snapshot');
    this.active = active;
    const storedPack = deps.sink.getPack(config.tenant_id, active.pack_id, active.pack_serial);
    if (!storedPack) throw new ClosedError('NOT_READY', 'active pack missing');
    this.pack = storedPack.pack;
    this.rules = [...compileBaseline(), ...compilePackRules(this.pack.body.rules as unknown as JsonValue)];
    if (config.mode === 'required') {
      this.artifact = this.pack.body.model;
      this.artifactHash = this.artifact ? modelHash(this.artifact) : null;
      if (active.snapshot.model_hash !== this.artifactHash) {
        throw new ClosedError('NOT_READY', 'model hash mismatch');
      }
    } else {
      this.artifact = null;
      this.artifactHash = null;
    }
  }

  // -- injected pieces ------------------------------------------------------

  private mono(): number {
    return this.deps.clock.mono();
  }

  private now(): number {
    return this.deps.clock.now();
  }

  // -- admission ------------------------------------------------------------

  // Validates the request, applies idempotency, readiness, and capacity, pins
  // the active snapshot, reserves decision/receipt IDs. Returns a Ctx for a
  // new screening, or a committed ScreenResponse for an idempotent retry.
  admit(requestJson: unknown): { ctx?: Ctx; cached?: ScreenResponse } {
    const req = validateScreenRequest(requestJson);
    const cand = req.candidate;
    const inputHash = sha256Hex(jcs(cand as unknown as JsonValue));
    const bindingHash = sha256Hex(jcs(cand.binding as unknown as JsonValue));
    const sink = this.deps.sink;

    const existing = sink.getDecision(cand.binding.tenant_id, cand.binding.gateway_id, cand.result_id);
    if (existing) {
      if (existing.input_hash !== inputHash || existing.binding_hash !== bindingHash) {
        throw new ClosedError('CONFLICT', 'result id reused with different input');
      }
      // equal input: cached path requires the pinned snapshot to still be active
      if (!this.snapshotActive(existing.epoch)) {
        throw new ClosedError('STALE_POLICY', 'pinned snapshot no longer active');
      }
      const receipt = sink.getReceiptById(existing.receipt_id);
      if (!receipt) throw new ClosedError('STORAGE_UNAVAILABLE', 'decision without receipt');
      const envelope = this.reconstructEnvelope(existing.decision, cand, receipt);
      return {
        cached: { v: 1, decision: existing.decision, envelope, receipt, cached: true },
      };
    }
    const byBinding = sink.getDecisionByBinding(cand.binding.tenant_id, cand.binding.gateway_id, bindingHash);
    if (byBinding) throw new ClosedError('CONFLICT', 'invocation slot reused');

    // readiness: active snapshot usable
    if (!this.snapshotActive(this.active.epoch)) {
      throw new ClosedError('NOT_READY', 'no active unexpired policy');
    }
    if (cand.binding.tenant_id !== this.config.tenant_id || cand.binding.gateway_id !== this.config.gateway_id) {
      throw new ClosedError('FORBIDDEN', 'binding outside configured tenant/gateway');
    }
    if (this.inflight >= this.config.max_inflight) {
      throw new ClosedError('RATE_LIMITED', 'admission cap');
    }

    this.inflight++;
    const ctx: Ctx = {
      req,
      candidate: cand,
      inputHash,
      bindingHash,
      snapshot: this.active.snapshot,
      decisionId: this.deps.ids.next('lsdec'),
      receiptId: this.deps.ids.next('lsrcp'),
      t0: this.mono(),
      findings: [],
      replacements: [],
      verdict: 'pass',
      reason: null,
      holdReason: null,
      data: [],
      quarantineId: null,
      policyResult: null,
      reducedCoverage: false,
      stageMs: { admission: 0, rules: 0, model: 0, lexshield: 0, audit: 0, render: 0 },
      state: 'admitted',
      committed: null,
      cachedResult: false,
      modelElapsed: 0,
      modelPositive: [],
    };
    return { ctx };
  }

  private snapshotActive(epoch: number): boolean {
    const a = this.deps.sink.getActiveSnapshot(this.config.tenant_id, this.config.gateway_id);
    if (!a || a.epoch !== epoch) return false;
    if (this.now() >= a.pack_expires_at_ms) return false;
    return true;
  }

  private refreshActive(): void {
    const a = this.deps.sink.getActiveSnapshot(this.config.tenant_id, this.config.gateway_id);
    if (a) this.active = a;
  }

  private deadlineExceeded(ctx: Ctx): boolean {
    return this.mono() - ctx.t0 >= BUDGET.hard;
  }

  private checkDeadline(ctx: Ctx): void {
    if (this.deadlineExceeded(ctx)) {
      this.discard(ctx);
      throw new ClosedError('DEADLINE', 'hard deadline');
    }
  }

  // -- local stages: rules -> model -> transform ----------------------------

  runLocal(ctx: Ctx): void {
    if (ctx.state !== 'admitted') throw new ClosedError('INTERNAL', 'bad state');
    const s0 = this.mono();
    this.checkDeadline(ctx);
    ctx.state = 'rules';
    const blockLens = ctx.candidate.blocks.map((b) => Buffer.byteLength(b.text, 'utf8'));
    let views: import('./normalize.ts').CandidateViews | null = null;
    try {
      views = buildViews(ctx.candidate.blocks);
      const findings: Finding[] = [];
      for (const view of views.ruleViews) {
        for (const rule of this.rules) {
          for (const alt of rule.alternatives) {
            for (const sp of matchRuleInView(view, alt, blockLens)) {
              findings.push({ rule_id: rule.id, class: rule.cls, span: sp });
            }
          }
        }
      }
      for (const input of views.predicateInputs) {
        for (const hit of encodingFindings(input, blockLens)) {
          findings.push({ rule_id: 'builtin.encoding', class: 'encoding', span: hit });
        }
      }
      ctx.findings = dedupSortFindings(findings);
    } catch (e) {
      if (e instanceof HoldSignal) {
        ctx.holdReason = e.reason;
        ctx.verdict = 'hold';
        ctx.reason = e.reason;
      } else throw e;
    }
    ctx.stageMs.rules += this.mono() - s0;
    this.checkDeadline(ctx);

    // finding cap
    if (ctx.holdReason === null && ctx.findings.length > FINDING_CAP) {
      ctx.findings = ctx.findings.slice(0, FINDING_CAP);
      this.proposeHold(ctx, 'FINDING_LIMIT');
    }
    if (ctx.holdReason === null && ctx.findings.some((f) => this.actionOf(f.rule_id) === 'hold')) {
      this.proposeHold(ctx, 'RULE_BLOCK');
    }

    // model stage
    const mode = this.modeOverride ?? this.config.mode;
    if (ctx.holdReason === null && mode === 'required') {
      ctx.state = 'model';
      const m0 = this.mono();
      this.runModel(ctx, views);
      ctx.modelElapsed = this.mono() - m0;
      ctx.stageMs.model += ctx.modelElapsed;
      // A completed positive result stands only when it arrived inside the
      // model budget; a valid response at/after 80 ms is a timeout.
      if (ctx.holdReason === null && ctx.modelPositive.length > 0 && ctx.modelElapsed < BUDGET.model) {
        for (const c of ctx.modelPositive) {
          ctx.findings.push({ rule_id: `model.${c}`, class: c, span: null });
        }
        ctx.findings = dedupSortFindings(ctx.findings);
        this.proposeHold(ctx, 'MODEL_BLOCK');
      } else if (ctx.holdReason === null && ctx.modelElapsed >= BUDGET.model) {
        this.proposeHold(ctx, 'MODEL_TIMEOUT');
      }
      this.checkDeadline(ctx);
    } else if (ctx.holdReason === null && mode === 'rules_only') {
      ctx.reducedCoverage = true;
    }

    // transform stage
    ctx.state = 'transform';
    const t0 = this.mono();
    this.runTransform(ctx, blockLens);
    ctx.stageMs.rules += this.mono() - t0;
    this.checkDeadline(ctx);
    ctx.state = 'policy';
  }

  private actionOf(ruleId: string): 'strip' | 'hold' {
    const r = this.rules.find((x) => x.id === ruleId);
    return r ? r.action : 'hold';
  }

  private proposeHold(ctx: Ctx, reason: ProposedHold): void {
    if (ctx.holdReason === null) {
      ctx.holdReason = reason;
      ctx.verdict = 'hold';
      ctx.reason = reason;
    }
  }

  private runModel(ctx: Ctx, views: import('./normalize.ts').CandidateViews | null): void {
    if (this.artifact === null || this.artifactHash === null) {
      this.proposeHold(ctx, 'MODEL_REQUIRED');
      return;
    }
    let features: string[];
    try {
      const rv = views ?? buildViews(ctx.candidate.blocks);
      const set = featurize(rv.ruleViews);
      if (set.size > 32768) {
        this.proposeHold(ctx, 'LIMIT');
        return;
      }
      features = [...set].sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
    } catch (e) {
      if (e instanceof HoldSignal) {
        this.proposeHold(ctx, e.reason);
        return;
      }
      throw e;
    }
    const port = this.modelPort ?? ((req) => modelScore(this.artifact!, req.features));
    let resp: ModelResponse;
    try {
      resp = port({ v: 1, model_hash: this.artifactHash, features });
    } catch (e) {
      if (e instanceof ClosedError && e.code === 'NOT_FOUND') {
        this.proposeHold(ctx, 'MODEL_REQUIRED');
        return;
      }
      this.proposeHold(ctx, 'MODEL_INVALID');
      return;
    }
    // validate response: exact schema + pinned hash + arithmetic agreement
    let invalid = false;
    try {
      if (Object.keys(resp as object).sort().join(',') !== 'model_hash,positive,scores,v') {
        invalid = true;
      }
      if (
        resp.v !== 1 ||
        resp.model_hash !== this.artifactHash ||
        !Array.isArray(resp.scores) ||
        resp.scores.length !== 3 ||
        !resp.scores.every((s) => Number.isInteger(s)) ||
        !Array.isArray(resp.positive) ||
        !resp.positive.every((c) => (MODEL_CLASSES as readonly string[]).includes(c)) ||
        new Set(resp.positive).size !== resp.positive.length
      ) {
        invalid = true;
      }
      const expected = modelScore(this.artifact, features);
      if (
        !invalid &&
        (resp.scores.join(',') !== expected.scores.join(',') ||
          resp.positive.join(',') !== expected.positive.join(','))
      ) {
        invalid = true;
      }
    } catch {
      invalid = true;
    }
    if (invalid) {
      this.proposeHold(ctx, 'MODEL_INVALID');
      return;
    }
    ctx.modelPositive = [...resp.positive];
  }

  // Transform: merge strip spans, apply replacements, closure pass.
  private runTransform(ctx: Ctx, blockLens: number[]): void {
    if (ctx.holdReason !== null) {
      ctx.data = [];
      ctx.replacements = [];
      return;
    }
    const stripSpans = ctx.findings.filter((f) => this.actionOf(f.rule_id) === 'strip' && f.span !== null).map((f) => f.span!);
    if (stripSpans.length === 0) {
      ctx.data = ctx.candidate.blocks;
      ctx.verdict = 'pass';
      return;
    }
    // union overlapping/adjacent spans per block
    const merged = mergeSpans(stripSpans);
    if (merged.length > 64) {
      this.proposeHold(ctx, 'FINDING_LIMIT');
      ctx.data = [];
      ctx.replacements = [];
      return;
    }
    ctx.replacements = merged;
    const { blocks: newBlocks, markerRanges } = applyReplacements(ctx.candidate.blocks, merged);
    // closure pass: rescan transformed text with rules (+ required model)
    const closureFindings = this.closureScan(ctx, newBlocks, markerRanges, blockLens);
    if (closureFindings.length > 0) {
      ctx.findings = dedupSortFindings([...ctx.findings, ...closureFindings]);
      const modelHit = closureFindings.some((f) => f.rule_id.startsWith('model.'));
      this.proposeHold(ctx, modelHit ? 'MODEL_BLOCK' : 'RULE_BLOCK');
      ctx.data = [];
      ctx.replacements = [];
      ctx.verdict = 'hold';
      return;
    }
    ctx.data = newBlocks;
    ctx.verdict = 'strip';
    ctx.reason = 'STRIPPED';
  }

  // Rescans transformed text. Findings touching inserted marker bytes become
  // whole-result findings; others map back to original-byte spans.
  private closureScan(
    ctx: Ctx,
    blocks: TextBlock[],
    markerRanges: Map<number, [number, number][]>,
    origBlockLens: number[],
  ): Finding[] {
    const out: Finding[] = [];
    const newLens = blocks.map((b) => Buffer.byteLength(b.text, 'utf8'));
    let views;
    try {
      views = buildViews(blocks);
    } catch (e) {
      if (e instanceof HoldSignal) {
        // resource failure during closure -> hold RULE_BLOCK equivalent: the
        // safest mapping is a whole-result LIMIT hold
        out.push({ rule_id: 'builtin.encoding', class: 'encoding', span: null });
        return out;
      }
      throw e;
    }
    const mapSpan = (sp: Span): Span | null => {
      // new-text span -> original coords; if it intersects a marker range -> null
      const marks = markerRanges.get(sp.block) ?? [];
      for (const [ms, me] of marks) {
        if (sp.start < me && sp.end > ms) return null;
      }
      // map back via replacements of that block
      const reps = (ctx.replacements ?? []).filter((r) => r.block === sp.block).sort((a, b) => a.start - b.start);
      const start = mapNewToOrig(sp.start, reps, markerRanges.get(sp.block) ?? []);
      const end = mapNewToOrig(sp.end - 1, reps, markerRanges.get(sp.block) ?? []) + 1;
      if (start < 0 || end < 0 || end > (origBlockLens[sp.block] ?? 0)) return null;
      return { block: sp.block, start, end };
    };
    for (const view of views.ruleViews) {
      for (const rule of this.rules) {
        for (const alt of rule.alternatives) {
          for (const sp of matchRuleInView(view, alt, newLens)) {
            out.push({ rule_id: rule.id, class: rule.cls, span: mapSpan(sp) });
          }
        }
      }
    }
    for (const input of views.predicateInputs) {
      for (const hit of encodingFindings(input, newLens)) {
        out.push({ rule_id: 'builtin.encoding', class: 'encoding', span: mapSpan(hit) });
      }
    }
    const mode = this.modeOverride ?? this.config.mode;
    if (mode === 'required' && this.artifact) {
      try {
        const set = featurize(views.ruleViews);
        if (set.size <= 32768) {
          const features = [...set].sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
          const resp = modelScore(this.artifact, features);
          for (const c of resp.positive) out.push({ rule_id: `model.${c}`, class: c, span: null });
        }
      } catch {
        /* a closure model failure surfaces as MODEL_INVALID upstream */
        out.push({ rule_id: 'model.override', class: 'override', span: null });
      }
    }
    return out;
  }

  // -- policy ---------------------------------------------------------------

  runPolicy(ctx: Ctx): void {
    if (ctx.state !== 'policy') throw new ClosedError('INTERNAL', 'bad state');
    this.checkDeadline(ctx);
    const s0 = this.mono();
    const classes = uniqueClasses(ctx.findings);
    const req = {
      v: 1 as const,
      request_id: ctx.req.request_id,
      binding: ctx.candidate.binding,
      input_hash: ctx.inputHash,
      snapshot: ctx.snapshot,
      candidate_verdict: ctx.verdict,
      classes,
    };
    let resp: PolicyResponse | null = null;
    try {
      const r = this.deps.lexshield.evaluateReturn(req);
      if (r && r.v === 1 && r.policy_hash === this.deps.lexshield.policyHash) {
        resp = r;
      }
    } catch {
      resp = null;
    }
    ctx.stageMs.lexshield = this.mono() - s0;
    if (ctx.stageMs.lexshield >= BUDGET.lexshield) resp = null;
    if (resp === null) {
      this.proposeHold(ctx, 'LEXSHIELD_TIMEOUT');
    } else if (resp.disposition === 'block') {
      this.proposeHold(ctx, 'LEXSHIELD_BLOCK');
    }
    ctx.policyResult = resp;
    ctx.state = 'sealing';
    this.checkDeadline(ctx);
  }

  // -- sealing / commit -----------------------------------------------------

  seal(ctx: Ctx): void {
    if (ctx.state !== 'sealing') {
      // allow 'seal' event to run remaining local stages first
      if (ctx.state === 'admitted') this.runLocal(ctx);
      if (ctx.state === 'policy') this.runPolicy(ctx);
    }
    if (ctx.state !== 'sealing') throw new ClosedError('INTERNAL', 'bad state');
    this.refreshActive();
    if (this.active.epoch !== ctx.snapshot.epoch) {
      this.proposeHold(ctx, 'POLICY_CHANGED');
    } else if (this.now() >= this.active.pack_expires_at_ms) {
      this.proposeHold(ctx, 'PACK_EXPIRED');
    }
    this.checkDeadline(ctx);
    const s0 = this.mono();

    if (ctx.verdict === 'hold') {
      ctx.data = [];
      ctx.replacements = [];
      ctx.quarantineId = this.deps.ids.next('lsq');
    }
    const notice =
      ctx.verdict === 'pass' ? null : ctx.verdict === 'strip' ? STRIP_NOTICE : HOLD_NOTICE;
    const envelope: DataEnvelope = {
      type: 'lexsieve.tool-data.v1',
      result_id: ctx.candidate.result_id,
      decision_id: ctx.decisionId,
      receipt_id: ctx.receiptId,
      trust: 'untrusted',
      disposition: ctx.verdict,
      provenance: {
        tool: ctx.candidate.binding.tool,
        adapter: ctx.candidate.binding.adapter,
        content_sha256: sha256Hex(jcs(ctx.candidate.blocks as unknown as JsonValue)),
      },
      notice,
      data: ctx.data,
    };
    const decision: Decision = {
      decision_id: ctx.decisionId,
      result_id: ctx.candidate.result_id,
      input_hash: ctx.inputHash,
      snapshot: ctx.snapshot,
      policy_result: ctx.policyResult,
      verdict: ctx.verdict,
      reason: ctx.reason ?? 'CLEAN',
      findings: dedupSortFindings(ctx.findings).slice(0, FINDING_CAP),
      replacements: [...ctx.replacements].sort(spanCmp),
      output_hash: sha256Hex(jcs(envelope as unknown as JsonValue)),
      quarantine_id: ctx.quarantineId,
    };
    const signer = this.deps.signer;
    const recordedAt = this.now();
    const res = this.deps.sink.commit(
      ctx.candidate.binding.tenant_id,
      ctx.candidate.binding.gateway_id,
      ctx.candidate.result_id,
      ctx.inputHash,
      ctx.bindingHash,
      ctx.snapshot.epoch,
      (seq, prevHash) => {
        const body: ReceiptBody = {
          v: 1,
          receipt_id: ctx.receiptId,
          tenant_id: ctx.candidate.binding.tenant_id,
          gateway_id: ctx.candidate.binding.gateway_id,
          seq,
          recorded_at_ms: recordedAt,
          prev_hash: prevHash,
          decision,
        };
        const { hash, signature } = signReceipt(body, signer.seed);
        const receipt = { body, hash, key_id: signer.keyId, signature };
        const quarantine: QuarantineMetadata | null =
          ctx.verdict === 'hold'
            ? {
                v: 1,
                type: 'lexsieve.quarantine.v1',
                content_kind: decision.findings.length > 0 ? 'suspected_instruction' : 'unclassified',
                quarantine_id: ctx.quarantineId!,
                result_id: ctx.candidate.result_id,
                receipt_id: ctx.receiptId,
                expires_at_ms: recordedAt + this.config.retention_days * 86400000,
              }
            : null;
        return { receipt, decision, quarantine };
      },
    );
    if (res.status === 'exists' || res.status === 'binding_conflict') {
      // a racing commit won; adopt its decision through the cached path
      const stored = res.stored;
      if (stored.input_hash !== ctx.inputHash || stored.binding_hash !== ctx.bindingHash) {
        this.discard(ctx);
        throw new ClosedError('CONFLICT', 'racing commit conflict');
      }
      const receipt = this.deps.sink.getReceiptById(stored.receipt_id);
      if (!receipt) throw new ClosedError('STORAGE_UNAVAILABLE', 'decision without receipt');
      const envelope2 = this.reconstructEnvelope(stored.decision, ctx.candidate, receipt);
      ctx.committed = { decision: stored.decision, envelope: envelope2, receipt };
      ctx.cachedResult = true;
      ctx.state = 'committed';
      ctx.stageMs.audit = this.mono() - s0;
      return;
    }
    ctx.committed = { decision, envelope, receipt: res.receipt };
    ctx.state = 'committed';
    ctx.stageMs.audit = this.mono() - s0;
  }

  // -- handoff --------------------------------------------------------------

  handoff(ctx: Ctx): DataEnvelope {
    if (ctx.state !== 'committed') {
      if (ctx.state === 'admitted' || ctx.state === 'policy') {
        this.seal(ctx);
      }
    }
    if (!ctx.committed) throw new ClosedError('INTERNAL', 'no committed decision');
    this.refreshActive();
    const stale =
      this.active.epoch !== ctx.snapshot.epoch || this.now() >= this.active.pack_expires_at_ms;
    if (stale) {
      this.discard(ctx);
      throw new ClosedError('STALE_POLICY', 'epoch/expiry before handoff');
    }
    ctx.state = 'handed_off';
    const e = ctx.committed.envelope;
    ctx.state = 'done';
    this.inflight--;
    return e;
  }

  // Full screen(): admit -> local -> policy -> seal -> handoff.
  screen(requestJson: unknown): ScreenResponse {
    const { ctx, cached } = this.admit(requestJson);
    if (cached) return cached;
    try {
      this.runLocal(ctx!);
      this.runPolicy(ctx!);
      this.seal(ctx!);
      this.handoff(ctx!);
    } catch (e) {
      if (ctx!.state !== 'committed' && ctx!.state !== 'done' && ctx!.state !== 'discarded') {
        this.discard(ctx!);
      }
      throw e;
    }
    return {
      v: 1,
      decision: ctx!.committed!.decision,
      envelope: ctx!.committed!.envelope,
      receipt: ctx!.committed!.receipt,
      cached: ctx!.cachedResult,
    };
  }

  discard(ctx: Ctx): void {
    if (ctx.state !== 'done' && ctx.state !== 'discarded') {
      ctx.state = 'discarded';
      this.inflight = Math.max(0, this.inflight - 1);
    }
  }

  private reconstructEnvelope(
    decision: Decision,
    cand: Candidate,
    receipt: import('./schema.ts').SignedReceipt,
  ): DataEnvelope {
    let data: TextBlock[] = [];
    if (decision.verdict === 'pass') {
      data = cand.blocks;
    } else if (decision.verdict === 'strip') {
      data = applyReplacements(cand.blocks, decision.replacements).blocks;
    }
    const notice =
      decision.verdict === 'pass' ? null : decision.verdict === 'strip' ? STRIP_NOTICE : HOLD_NOTICE;
    return {
      type: 'lexsieve.tool-data.v1',
      result_id: cand.result_id,
      decision_id: decision.decision_id,
      receipt_id: receipt.body.receipt_id,
      trust: 'untrusted',
      disposition: decision.verdict,
      provenance: {
        tool: cand.binding.tool,
        adapter: cand.binding.adapter,
        content_sha256: sha256Hex(jcs(cand.blocks as unknown as JsonValue)),
      },
      notice,
      data,
    };
  }

  screenMs(ctx: Ctx): number {
    return Math.round(this.mono() - ctx.t0);
  }

  // Replay support: build a side-effect-free context pinned to a recorded
  // snapshot. No idempotency check, no inflight accounting, no ID allocation
  // beyond reusing the recorded ones.
  bareCtx(req: ScreenRequest, snapshot: Snapshot): Ctx {
    const cand = req.candidate;
    return {
      req,
      candidate: cand,
      inputHash: sha256Hex(jcs(cand as unknown as JsonValue)),
      bindingHash: sha256Hex(jcs(cand.binding as unknown as JsonValue)),
      snapshot,
      decisionId: 'lsdec_000000000000000000000',
      receiptId: 'lsrcp_000000000000000000000',
      t0: this.mono(),
      findings: [],
      replacements: [],
      verdict: 'pass',
      reason: null,
      holdReason: null,
      data: [],
      quarantineId: null,
      policyResult: null,
      reducedCoverage: false,
      stageMs: { admission: 0, rules: 0, model: 0, lexshield: 0, audit: 0, render: 0 },
      state: 'admitted',
      committed: null,
      cachedResult: false,
      modelElapsed: 0,
      modelPositive: [],
    };
  }
}

// ---------------------------------------------------------------------------

function spanCmp(a: Span, b: Span): number {
  return a.block - b.block || a.start - b.start || a.end - b.end;
}

function mergeSpans(spans: Span[]): Span[] {
  const byBlock = new Map<number, [number, number][]>();
  for (const s of spans) {
    const arr = byBlock.get(s.block) ?? [];
    arr.push([s.start, s.end]);
    byBlock.set(s.block, arr);
  }
  const out: Span[] = [];
  for (const [block, arr] of byBlock) {
    arr.sort((a, b) => a[0] - b[0]);
    let [cs, ce] = arr[0]!;
    for (let i = 1; i < arr.length; i++) {
      const [s, e] = arr[i]!;
      if (s <= ce) ce = Math.max(ce, e);
      else {
        out.push({ block, start: cs, end: ce });
        [cs, ce] = [s, e];
      }
    }
    out.push({ block, start: cs, end: ce });
  }
  return out.sort(spanCmp);
}

// Applies replacements to blocks, returning new blocks plus the byte ranges
// (in new-text coordinates) occupied by inserted markers, per block.
export function applyReplacements(
  blocks: TextBlock[],
  replacements: Span[],
): { blocks: TextBlock[]; markerRanges: Map<number, [number, number][]> } {
  const markerRanges = new Map<number, [number, number][]>();
  const out: TextBlock[] = [];
  for (const b of blocks) {
    const reps = replacements.filter((r) => r.block === b.index).sort((a, b2) => b2.start - a.start);
    // work on UTF-8 bytes
    let bytes = Buffer.from(b.text, 'utf8');
    const marks: [number, number][] = [];
    const applied: { start: number; end: number }[] = [];
    for (const r of reps) {
      bytes = Buffer.concat([bytes.subarray(0, r.start), Buffer.from(REMOVED, 'utf8'), bytes.subarray(r.end)]);
      applied.push({ start: r.start, end: r.start + REMOVED.length });
    }
    // applied is in descending order; normalize to ascending marker ranges
    applied.sort((a, b) => a.start - b.start);
    for (const a of applied) marks.push([a.start, a.end]);
    if (marks.length) markerRanges.set(b.index, marks);
    out.push({ index: b.index, text: bytes.toString('utf8') });
  }
  return { blocks: out, markerRanges };
}

// Maps a byte offset in transformed text back to original coordinates using
// the sorted replacements and marker ranges of that block.
function mapNewToOrig(
  off: number,
  reps: Span[],
  marks: [number, number][],
): number {
  // walk replacements ascending; each maps [origStart,origEnd) -> [newStart,newEnd marker)
  let delta = 0;
  for (const r of reps) {
    const newStart = r.start - delta;
    const markerLen = REMOVED.length;
    const removedLen = r.end - r.start;
    if (off < newStart) break;
    if (off < newStart + markerLen) return -1; // inside marker
    delta += removedLen - markerLen;
  }
  void marks;
  return off + delta;
}

function uniqueClasses(findings: Finding[]): Class[] {
  const set = new Set(findings.map((f) => f.class));
  return CLASS_ORDER.filter((c) => set.has(c));
}
