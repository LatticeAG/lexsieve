// Section 10.1: local SQLite sink. WAL, synchronous=FULL, foreign_keys=ON,
// busy_timeout=10 ms, one writer coordinator per gateway, prepared
// statements. The schema below is the complete logical v1 schema.

import { DatabaseSync } from 'node:sqlite';
import { ClosedError } from './errors.ts';
import { jcs, parseJson } from './jcs.ts';
import {
  validateDecision,
  validateSignedReceipt,
  validateSignedPack,
  type Decision,
  type QuarantineMetadata,
  type SignedPack,
  type SignedReceipt,
} from './schema.ts';
import type {
  ActiveSnapshotRecord,
  ChainHead,
  CommitResult,
  Sink,
  StoredDecision,
  StoredPack,
  TelemetrySpoolRow,
} from './sink.ts';

export const SCHEMA_V1 = `
CREATE TABLE schema_version(version INTEGER PRIMARY KEY, installed_at_ms INTEGER NOT NULL);
CREATE TABLE chain_heads(tenant_id TEXT NOT NULL, gateway_id TEXT NOT NULL, seq INTEGER NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(tenant_id,gateway_id));
CREATE TABLE receipts(tenant_id TEXT NOT NULL, gateway_id TEXT NOT NULL, seq INTEGER NOT NULL, receipt_id TEXT NOT NULL UNIQUE, hash TEXT NOT NULL UNIQUE, json TEXT NOT NULL, recorded_at_ms INTEGER NOT NULL, PRIMARY KEY(tenant_id,gateway_id,seq));
CREATE TABLE decisions(tenant_id TEXT NOT NULL, gateway_id TEXT NOT NULL, result_id TEXT NOT NULL, input_hash TEXT NOT NULL, epoch INTEGER NOT NULL, receipt_id TEXT NOT NULL, binding_hash TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY(tenant_id,gateway_id,result_id), UNIQUE(tenant_id,gateway_id,binding_hash), FOREIGN KEY(receipt_id) REFERENCES receipts(receipt_id));
CREATE TABLE quarantine(quarantine_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, gateway_id TEXT NOT NULL, result_id TEXT NOT NULL, receipt_id TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, json TEXT NOT NULL, FOREIGN KEY(receipt_id) REFERENCES receipts(receipt_id));
CREATE TABLE packs(tenant_id TEXT NOT NULL, pack_id TEXT NOT NULL, serial INTEGER NOT NULL, hash TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY(tenant_id,pack_id,serial), UNIQUE(tenant_id,hash));
CREATE TABLE active_snapshot(tenant_id TEXT NOT NULL, gateway_id TEXT NOT NULL, epoch INTEGER NOT NULL, json TEXT NOT NULL, PRIMARY KEY(tenant_id,gateway_id));
CREATE TABLE telemetry_spool(batch_id TEXT PRIMARY KEY, json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL, next_attempt_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL);
CREATE INDEX receipts_retention ON receipts(recorded_at_ms);
CREATE INDEX quarantine_expiry ON quarantine(expires_at_ms);
`;

interface Row {
  [k: string]: string | number | bigint | null;
}

export class SqliteSink implements Sink {
  private db: DatabaseSync;
  failCommit = false;

  constructor(path: string) {
    try {
      this.db = new DatabaseSync(path);
    } catch (e) {
      throw new ClosedError('STORAGE_UNAVAILABLE', `sqlite open: ${(e as Error).message}`);
    }
    this.db.exec('PRAGMA journal_mode=WAL');
    this.db.exec('PRAGMA synchronous=FULL');
    this.db.exec('PRAGMA foreign_keys=ON');
    this.db.exec('PRAGMA busy_timeout=10');
  }

  open(): void {
    // migration 0 -> 1
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const v = this.db.prepare('SELECT version FROM schema_version ORDER BY version DESC LIMIT 1').get() as Row | undefined;
      this.db.exec('COMMIT');
      if (v && Number(v['version']) > 1) {
        throw new ClosedError('NOT_READY', 'schema version newer than supported');
      }
      if (v) return;
    } catch (e) {
      this.db.exec('ROLLBACK');
      if (e instanceof ClosedError) throw e;
      // table does not exist yet -> migrate
    }
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.exec(SCHEMA_V1);
      this.db.prepare('INSERT INTO schema_version(version, installed_at_ms) VALUES (1, ?)').run(Date.now());
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw new ClosedError('STORAGE_UNAVAILABLE', `migration failed: ${(e as Error).message}`);
    }
  }

  close(): void {
    this.db.close();
  }

  private get(sql: string, ...params: (string | number)[]): Row | undefined {
    return this.db.prepare(sql).get(...params) as Row | undefined;
  }

  private run(sql: string, ...params: (string | number)[]): void {
    this.db.prepare(sql).run(...params);
  }

  getDecision(tenant: string, gateway: string, resultId: string): StoredDecision | null {
    const r = this.get(
      'SELECT input_hash, binding_hash, epoch, receipt_id, json FROM decisions WHERE tenant_id=? AND gateway_id=? AND result_id=?',
      tenant, gateway, resultId,
    );
    if (!r) return null;
    return {
      result_id: resultId,
      input_hash: String(r['input_hash']),
      binding_hash: String(r['binding_hash']),
      epoch: Number(r['epoch']),
      receipt_id: String(r['receipt_id']),
      decision: validateDecision(parseJson(String(r['json']))),
    };
  }

  getDecisionByBinding(tenant: string, gateway: string, bindingHash: string): StoredDecision | null {
    const r = this.get(
      'SELECT result_id, input_hash, binding_hash, epoch, receipt_id, json FROM decisions WHERE tenant_id=? AND gateway_id=? AND binding_hash=?',
      tenant, gateway, bindingHash,
    );
    if (!r) return null;
    return {
      result_id: String(r['result_id']),
      input_hash: String(r['input_hash']),
      binding_hash: bindingHash,
      epoch: Number(r['epoch']),
      receipt_id: String(r['receipt_id']),
      decision: validateDecision(parseJson(String(r['json']))),
    };
  }

  getReceiptById(receiptId: string): SignedReceipt | null {
    const r = this.get('SELECT json FROM receipts WHERE receipt_id=?', receiptId);
    return r ? validateSignedReceipt(parseJson(String(r['json']))) : null;
  }

  getChainHead(tenant: string, gateway: string): ChainHead | null {
    const r = this.get('SELECT seq, hash FROM chain_heads WHERE tenant_id=? AND gateway_id=?', tenant, gateway);
    return r ? { seq: Number(r['seq']), hash: String(r['hash']) } : null;
  }

  getReceiptBySeq(tenant: string, gateway: string, seq: number): SignedReceipt | null {
    const r = this.get('SELECT json FROM receipts WHERE tenant_id=? AND gateway_id=? AND seq=?', tenant, gateway, seq);
    return r ? validateSignedReceipt(parseJson(String(r['json']))) : null;
  }

  commit(
    tenant: string,
    gateway: string,
    resultId: string,
    inputHash: string,
    bindingHash: string,
    epoch: number,
    build: (seq: number, prevHash: string) => { receipt: SignedReceipt; decision: Decision; quarantine: QuarantineMetadata | null },
  ): CommitResult {
    if (this.failCommit) throw new ClosedError('STORAGE_UNAVAILABLE', 'sink unavailable');
    try {
      this.db.exec('BEGIN IMMEDIATE');
    } catch (e) {
      throw new ClosedError('STORAGE_UNAVAILABLE', `begin: ${(e as Error).message}`);
    }
    try {
      const existing = this.getDecision(tenant, gateway, resultId);
      if (existing) {
        this.db.exec('ROLLBACK');
        return { status: 'exists', stored: existing };
      }
      const byBinding = this.getDecisionByBinding(tenant, gateway, bindingHash);
      if (byBinding && byBinding.result_id !== resultId) {
        this.db.exec('ROLLBACK');
        return { status: 'binding_conflict', stored: byBinding };
      }
      const headRow = this.get('SELECT seq, hash FROM chain_heads WHERE tenant_id=? AND gateway_id=?', tenant, gateway);
      const seq = headRow ? Number(headRow['seq']) + 1 : 1;
      const prevHash = headRow ? String(headRow['hash']) : '0'.repeat(64);
      const { receipt, decision, quarantine } = build(seq, prevHash);
      this.run(
        'INSERT INTO receipts(tenant_id,gateway_id,seq,receipt_id,hash,json,recorded_at_ms) VALUES (?,?,?,?,?,?,?)',
        tenant, gateway, seq, receipt.body.receipt_id, receipt.hash, jcs(receipt as unknown as import('./jcs.ts').JsonValue), receipt.body.recorded_at_ms,
      );
      this.run(
        'INSERT INTO decisions(tenant_id,gateway_id,result_id,input_hash,epoch,receipt_id,binding_hash,json) VALUES (?,?,?,?,?,?,?,?)',
        tenant, gateway, resultId, inputHash, epoch, receipt.body.receipt_id, bindingHash, jcs(decision as unknown as import('./jcs.ts').JsonValue),
      );
      if (quarantine) {
        this.run(
          'INSERT INTO quarantine(quarantine_id,tenant_id,gateway_id,result_id,receipt_id,expires_at_ms,json) VALUES (?,?,?,?,?,?,?)',
          quarantine.quarantine_id, tenant, gateway, resultId, receipt.body.receipt_id, quarantine.expires_at_ms, jcs(quarantine as unknown as import('./jcs.ts').JsonValue),
        );
      }
      if (headRow) {
        this.run('UPDATE chain_heads SET seq=?, hash=? WHERE tenant_id=? AND gateway_id=?', seq, receipt.hash, tenant, gateway);
      } else {
        this.run('INSERT INTO chain_heads(tenant_id,gateway_id,seq,hash) VALUES (?,?,?,?)', tenant, gateway, seq, receipt.hash);
      }
      this.db.exec('COMMIT');
      return { status: 'committed', receipt };
    } catch (e) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* already rolled back */
      }
      if (e instanceof ClosedError) throw e;
      throw new ClosedError('STORAGE_UNAVAILABLE', `commit: ${(e as Error).message}`);
    }
  }

  putPack(tenant: string, pack: SignedPack): void {
    this.run(
      'INSERT OR IGNORE INTO packs(tenant_id,pack_id,serial,hash,json) VALUES (?,?,?,?,?)',
      tenant, pack.body.pack_id, pack.body.serial, pack.hash, jcs(pack as unknown as import('./jcs.ts').JsonValue),
    );
  }

  getPack(tenant: string, packId: string, serial: number): StoredPack | null {
    const r = this.get('SELECT hash, json FROM packs WHERE tenant_id=? AND pack_id=? AND serial=?', tenant, packId, serial);
    return r ? { tenant_id: tenant, pack_id: packId, serial, hash: String(r['hash']), pack: validateSignedPack(parseJson(String(r['json']))) } : null;
  }

  getPackByHash(tenant: string, hash: string): StoredPack | null {
    const r = this.get('SELECT pack_id, serial, json FROM packs WHERE tenant_id=? AND hash=?', tenant, hash);
    return r ? { tenant_id: tenant, pack_id: String(r['pack_id']), serial: Number(r['serial']), hash, pack: validateSignedPack(parseJson(String(r['json']))) } : null;
  }

  getMaxPackSerial(tenant: string, packId: string): number | null {
    const r = this.get('SELECT MAX(serial) AS m FROM packs WHERE tenant_id=? AND pack_id=?', tenant, packId);
    if (!r || r['m'] === null) return null;
    return Number(r['m']);
  }

  getActiveSnapshot(tenant: string, gateway: string): ActiveSnapshotRecord | null {
    const r = this.get('SELECT json FROM active_snapshot WHERE tenant_id=? AND gateway_id=?', tenant, gateway);
    if (!r) return null;
    return parseJson(String(r['json'])) as unknown as ActiveSnapshotRecord;
  }

  setActiveSnapshot(tenant: string, gateway: string, rec: ActiveSnapshotRecord): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.run(
        'INSERT INTO active_snapshot(tenant_id,gateway_id,epoch,json) VALUES (?,?,?,?) ON CONFLICT(tenant_id,gateway_id) DO UPDATE SET epoch=excluded.epoch, json=excluded.json',
        tenant, gateway, rec.epoch, jcs(rec as unknown as import('./jcs.ts').JsonValue),
      );
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw new ClosedError('STORAGE_UNAVAILABLE', `activate: ${(e as Error).message}`);
    }
  }

  getQuarantine(id: string): QuarantineMetadata | null {
    const r = this.get('SELECT json FROM quarantine WHERE quarantine_id=?', id);
    return r ? (parseJson(String(r['json'])) as unknown as QuarantineMetadata) : null;
  }

  spoolPut(row: TelemetrySpoolRow): void {
    this.run(
      'INSERT OR REPLACE INTO telemetry_spool(batch_id,json,state,attempts,next_attempt_ms,expires_at_ms) VALUES (?,?,?,?,?,?)',
      row.batch_id, row.json, row.state, row.attempts, row.next_attempt_ms, row.expires_at_ms,
    );
  }

  spoolDue(nowMs: number, maxBatches: number): TelemetrySpoolRow[] {
    const rows = this.db.prepare(
      'SELECT batch_id,json,state,attempts,next_attempt_ms,expires_at_ms FROM telemetry_spool WHERE state=? AND next_attempt_ms<=? ORDER BY expires_at_ms ASC LIMIT ?',
    ).all('pending', nowMs, maxBatches) as Row[];
    return rows.map((r) => ({
      batch_id: String(r['batch_id']),
      json: String(r['json']),
      state: r['state'] as TelemetrySpoolRow['state'],
      attempts: Number(r['attempts']),
      next_attempt_ms: Number(r['next_attempt_ms']),
      expires_at_ms: Number(r['expires_at_ms']),
    }));
  }

  spoolUpdate(row: TelemetrySpoolRow): void {
    this.spoolPut(row);
  }

  spoolCount(): number {
    const r = this.get('SELECT COUNT(*) AS c FROM telemetry_spool');
    return r ? Number(r['c']) : 0;
  }

  spoolBytes(): number {
    const r = this.get('SELECT COALESCE(SUM(LENGTH(json)),0) AS s FROM telemetry_spool');
    return r ? Number(r['s']) : 0;
  }

  spoolEvictOldest(n: number): number {
    const rows = this.db.prepare(
      'SELECT batch_id FROM telemetry_spool WHERE state=? ORDER BY expires_at_ms ASC LIMIT ?',
    ).all('pending', n) as Row[];
    for (const r of rows) this.run('DELETE FROM telemetry_spool WHERE batch_id=?', String(r['batch_id']));
    return rows.length;
  }

  receiptRange(tenant: string, gateway: string, fromSeq: number, toSeq: number): SignedReceipt[] {
    const rows = this.db.prepare(
      'SELECT json FROM receipts WHERE tenant_id=? AND gateway_id=? AND seq>=? AND seq<=? ORDER BY seq ASC',
    ).all(tenant, gateway, fromSeq, toSeq) as Row[];
    return rows.map((r) => validateSignedReceipt(parseJson(String(r['json']))));
  }

  receiptCount(): number {
    const r = this.get('SELECT COUNT(*) AS c FROM receipts');
    return r ? Number(r['c']) : 0;
  }

  verifyTail(tenant: string, gateway: string, n: number): boolean {
    const head = this.getChainHead(tenant, gateway);
    if (!head) return true;
    const last = this.getReceiptBySeq(tenant, gateway, head.seq);
    if (!last || last.hash !== head.hash) return false;
    let expectPrev = last.body.prev_hash;
    let seq = head.seq;
    let checked = 0;
    while (checked < n && seq > 1) {
      const prev = this.getReceiptBySeq(tenant, gateway, seq - 1);
      if (!prev || prev.hash !== expectPrev) return false;
      expectPrev = prev.body.prev_hash;
      seq--;
      checked++;
    }
    if (seq === 1 && expectPrev !== '0'.repeat(64)) return false;
    return true;
  }
}
