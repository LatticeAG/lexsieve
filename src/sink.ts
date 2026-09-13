// Section 10.1: persistence contract. One immediate transaction checks
// uniqueness, allocates seq, constructs/signs the receipt, inserts
// decision/quarantine, and advances the head. No raw input, sanitized
// content, model features, credential strings, or private signing keys are
// persisted.

import { ClosedError } from './errors.ts';
import type { Decision, QuarantineMetadata, SignedReceipt } from './schema.ts';
import { parseJson, jcs, type JsonValue } from './jcs.ts';
import { validateDecision, validateSignedReceipt } from './schema.ts';

export interface StoredDecision {
  result_id: string;
  input_hash: string;
  binding_hash: string;
  epoch: number;
  receipt_id: string;
  decision: Decision;
}

export interface ChainHead {
  seq: number;
  hash: string;
}

export interface ActiveSnapshotRecord {
  epoch: number;
  snapshot: import('./schema.ts').Snapshot;
  pack_id: string;
  pack_serial: number;
  pack_expires_at_ms: number;
  pack_hash: string;
}

export interface StoredPack {
  tenant_id: string;
  pack_id: string;
  serial: number;
  hash: string;
  pack: import('./schema.ts').SignedPack;
}

export interface TelemetrySpoolRow {
  batch_id: string;
  json: string;
  state: 'pending' | 'sending' | 'acknowledged' | 'rejected' | 'expired';
  attempts: number;
  next_attempt_ms: number;
  expires_at_ms: number;
}

// build is invoked inside the commit transaction with the allocated chain
// position; it returns the signed receipt and optional quarantine metadata.
export type CommitBuild = (
  seq: number,
  prevHash: string,
) => { receipt: SignedReceipt; decision: Decision; quarantine: QuarantineMetadata | null };

export type CommitResult =
  | { status: 'committed'; receipt: SignedReceipt }
  | { status: 'exists'; stored: StoredDecision }
  | { status: 'binding_conflict'; stored: StoredDecision };

export interface Sink {
  open(): void;
  close(): void;
  getDecision(tenant: string, gateway: string, resultId: string): StoredDecision | null;
  getDecisionByBinding(tenant: string, gateway: string, bindingHash: string): StoredDecision | null;
  getReceiptById(receiptId: string): SignedReceipt | null;
  getChainHead(tenant: string, gateway: string): ChainHead | null;
  getReceiptBySeq(tenant: string, gateway: string, seq: number): SignedReceipt | null;
  commit(
    tenant: string,
    gateway: string,
    resultId: string,
    inputHash: string,
    bindingHash: string,
    epoch: number,
    build: CommitBuild,
  ): CommitResult;
  // pack registry
  putPack(tenant: string, pack: import('./schema.ts').SignedPack): void;
  getPack(tenant: string, packId: string, serial: number): StoredPack | null;
  getPackByHash(tenant: string, hash: string): StoredPack | null;
  getMaxPackSerial(tenant: string, packId: string): number | null;
  // active snapshot
  getActiveSnapshot(tenant: string, gateway: string): ActiveSnapshotRecord | null;
  setActiveSnapshot(tenant: string, gateway: string, rec: ActiveSnapshotRecord): void;
  // quarantine
  getQuarantine(id: string): QuarantineMetadata | null;
  // telemetry spool
  spoolPut(row: TelemetrySpoolRow): void;
  spoolDue(nowMs: number, maxBatches: number): TelemetrySpoolRow[];
  spoolUpdate(row: TelemetrySpoolRow): void;
  spoolCount(): number;
  spoolBytes(): number;
  spoolEvictOldest(n: number): number;
  // audit
  receiptRange(tenant: string, gateway: string, fromSeq: number, toSeq: number): SignedReceipt[];
  receiptCount(): number;
  verifyTail(tenant: string, gateway: string, n: number): boolean;
}

// ---------------------------------------------------------------------------
// In-memory sink: same semantics as the SQLite sink, used by the conformance
// harness and embedders that provide their own storage.
// ---------------------------------------------------------------------------

export class MemorySink implements Sink {
  private decisions = new Map<string, StoredDecision>();
  private receipts = new Map<string, SignedReceipt>();
  private receiptsBySeq = new Map<string, SignedReceipt>();
  private heads = new Map<string, ChainHead>();
  private packs = new Map<string, StoredPack>();
  private active = new Map<string, ActiveSnapshotRecord>();
  private quarantine = new Map<string, QuarantineMetadata>();
  private spool = new Map<string, TelemetrySpoolRow>();
  // failure injection for fault-matrix tests
  failCommit = false;

  private kg(t: string, g: string) {
    return `${t}/${g}`;
  }

  open(): void {}
  close(): void {}

  getDecision(tenant: string, gateway: string, resultId: string): StoredDecision | null {
    return this.decisions.get(`${tenant}/${gateway}/${resultId}`) ?? null;
  }

  getDecisionByBinding(tenant: string, gateway: string, bindingHash: string): StoredDecision | null {
    const k = `${tenant}/${gateway}`;
    for (const d of this.decisions.values()) {
      if (d.binding_hash === bindingHash && this.decisions.get(`${k}/${d.result_id}`) === d) return d;
    }
    return null;
  }

  getReceiptById(receiptId: string): SignedReceipt | null {
    return this.receipts.get(receiptId) ?? null;
  }

  getChainHead(tenant: string, gateway: string): ChainHead | null {
    return this.heads.get(this.kg(tenant, gateway)) ?? null;
  }

  getReceiptBySeq(tenant: string, gateway: string, seq: number): SignedReceipt | null {
    return this.receiptsBySeq.get(`${tenant}/${gateway}/${seq}`) ?? null;
  }

  commit(
    tenant: string,
    gateway: string,
    resultId: string,
    inputHash: string,
    bindingHash: string,
    epoch: number,
    build: CommitBuild,
  ): CommitResult {
    if (this.failCommit) throw new ClosedError('STORAGE_UNAVAILABLE', 'sink unavailable');
    const dk = `${tenant}/${gateway}/${resultId}`;
    const existing = this.decisions.get(dk);
    if (existing) return { status: 'exists', stored: existing };
    const byBinding = this.getDecisionByBinding(tenant, gateway, bindingHash);
    if (byBinding && byBinding.result_id !== resultId) {
      return { status: 'binding_conflict', stored: byBinding };
    }
    const head = this.heads.get(this.kg(tenant, gateway)) ?? { seq: 0, hash: '0'.repeat(64) };
    const seq = head.seq + 1;
    const { receipt, decision, quarantine } = build(seq, head.hash);
    this.receipts.set(receipt.body.receipt_id, receipt);
    this.receiptsBySeq.set(`${tenant}/${gateway}/${seq}`, receipt);
    this.heads.set(this.kg(tenant, gateway), { seq, hash: receipt.hash });
    this.decisions.set(dk, {
      result_id: resultId,
      input_hash: inputHash,
      binding_hash: bindingHash,
      epoch,
      receipt_id: receipt.body.receipt_id,
      decision,
    });
    if (quarantine) this.quarantine.set(quarantine.quarantine_id, quarantine);
    return { status: 'committed', receipt };
  }

  putPack(tenant: string, pack: import('./schema.ts').SignedPack): void {
    this.packs.set(`${tenant}/${pack.body.pack_id}/${pack.body.serial}`, {
      tenant_id: tenant,
      pack_id: pack.body.pack_id,
      serial: pack.body.serial,
      hash: pack.hash,
      pack,
    });
  }

  getPack(tenant: string, packId: string, serial: number): StoredPack | null {
    return this.packs.get(`${tenant}/${packId}/${serial}`) ?? null;
  }

  getPackByHash(tenant: string, hash: string): StoredPack | null {
    for (const p of this.packs.values()) {
      if (p.tenant_id === tenant && p.hash === hash) return p;
    }
    return null;
  }

  getMaxPackSerial(tenant: string, packId: string): number | null {
    let max: number | null = null;
    for (const p of this.packs.values()) {
      if (p.tenant_id === tenant && p.pack_id === packId) {
        if (max === null || p.serial > max) max = p.serial;
      }
    }
    return max;
  }

  getActiveSnapshot(tenant: string, gateway: string): ActiveSnapshotRecord | null {
    return this.active.get(this.kg(tenant, gateway)) ?? null;
  }

  setActiveSnapshot(tenant: string, gateway: string, rec: ActiveSnapshotRecord): void {
    this.active.set(this.kg(tenant, gateway), rec);
  }

  getQuarantine(id: string): QuarantineMetadata | null {
    return this.quarantine.get(id) ?? null;
  }

  spoolPut(row: TelemetrySpoolRow): void {
    this.spool.set(row.batch_id, row);
  }

  spoolDue(nowMs: number, maxBatches: number): TelemetrySpoolRow[] {
    return [...this.spool.values()]
      .filter((r) => r.state === 'pending' && r.next_attempt_ms <= nowMs)
      .sort((a, b) => a.expires_at_ms - b.expires_at_ms)
      .slice(0, maxBatches);
  }

  spoolUpdate(row: TelemetrySpoolRow): void {
    this.spool.set(row.batch_id, row);
  }

  spoolCount(): number {
    return this.spool.size;
  }

  spoolBytes(): number {
    let n = 0;
    for (const r of this.spool.values()) n += r.json.length;
    return n;
  }

  spoolEvictOldest(n: number): number {
    const pending = [...this.spool.values()]
      .filter((r) => r.state === 'pending')
      .sort((a, b) => a.expires_at_ms - b.expires_at_ms);
    let evicted = 0;
    for (const r of pending.slice(0, n)) {
      this.spool.delete(r.batch_id);
      evicted++;
    }
    return evicted;
  }

  receiptRange(tenant: string, gateway: string, fromSeq: number, toSeq: number): SignedReceipt[] {
    const out: SignedReceipt[] = [];
    for (let s = fromSeq; s <= toSeq; s++) {
      const r = this.receiptsBySeq.get(`${tenant}/${gateway}/${s}`);
      if (!r) break;
      out.push(r);
    }
    return out;
  }

  receiptCount(): number {
    return this.receipts.size;
  }

  verifyTail(tenant: string, gateway: string, n: number): boolean {
    const head = this.heads.get(this.kg(tenant, gateway));
    if (!head) return true;
    const last = this.receiptsBySeq.get(`${tenant}/${gateway}/${head.seq}`);
    if (!last || last.hash !== head.hash) return false;
    // check the last n links
    let seq = head.seq;
    let expectPrev = last.body.prev_hash;
    let checked = 0;
    while (checked < n && seq > 1) {
      const prev = this.receiptsBySeq.get(`${tenant}/${gateway}/${seq - 1}`);
      if (!prev || prev.hash !== expectPrev) return false;
      expectPrev = prev.body.prev_hash;
      seq--;
      checked++;
    }
    if (seq === 1 && expectPrev !== '0'.repeat(64)) return false;
    return true;
  }
}

// Re-validate stored rows defensively (they were validated at insert time).
export function parseStoredDecision(json: string): Decision {
  return validateDecision(parseJson(json));
}

export function parseStoredReceipt(json: string): SignedReceipt {
  return validateSignedReceipt(parseJson(json));
}

export { jcs };
export type { JsonValue };
