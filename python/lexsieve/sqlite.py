"""Section 10.1: local SQLite sink. WAL, synchronous=FULL, foreign_keys=ON,
busy_timeout=10 ms, one writer coordinator per gateway. The schema below is
the complete logical v1 schema.

Uses the stdlib sqlite3 module with manual transaction control
(isolation_level=None) to mirror the reference implementation's
BEGIN IMMEDIATE / COMMIT / ROLLBACK discipline.
"""

import sqlite3
import time

from .errors import ClosedError
from .jcs import jcs, parse_json
from .schema import validate_decision, validate_signed_pack, validate_signed_receipt
from .sink import ZERO_HASH

SCHEMA_V1 = """
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
"""


class SqliteSink:
    def __init__(self, path):
        try:
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            raise ClosedError("STORAGE_UNAVAILABLE", f"sqlite open: {e}") from e
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=10")
        self.fail_commit = False

    def open(self):
        # migration 0 -> 1
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            ).fetchone()
            self.db.execute("COMMIT")
            if row and row["version"] > 1:
                raise ClosedError("NOT_READY", "schema version newer than supported")
            if row:
                return
        except ClosedError:
            self.db.execute("ROLLBACK")
            raise
        except sqlite3.Error:
            self.db.execute("ROLLBACK")
            # table does not exist yet -> migrate
        self.db.execute("BEGIN IMMEDIATE")
        try:
            # sqlite3's executescript implicitly commits; split statements
            # so the whole migration stays inside BEGIN IMMEDIATE.
            for stmt in SCHEMA_V1.split(";"):
                if stmt.strip():
                    self.db.execute(stmt)
            self.db.execute(
                "INSERT INTO schema_version(version, installed_at_ms) VALUES (1, ?)",
                (int(time.time() * 1000),),
            )
            self.db.execute("COMMIT")
        except sqlite3.Error as e:
            self.db.execute("ROLLBACK")
            raise ClosedError("STORAGE_UNAVAILABLE", f"migration failed: {e}") from e

    def close(self):
        self.db.close()

    def _get(self, sql, *params):
        return self.db.execute(sql, params).fetchone()

    def _run(self, sql, *params):
        self.db.execute(sql, params)

    def get_decision(self, tenant, gateway, result_id):
        r = self._get(
            "SELECT input_hash, binding_hash, epoch, receipt_id, json FROM decisions "
            "WHERE tenant_id=? AND gateway_id=? AND result_id=?",
            tenant, gateway, result_id,
        )
        if not r:
            return None
        return {
            "result_id": result_id,
            "input_hash": r["input_hash"],
            "binding_hash": r["binding_hash"],
            "epoch": r["epoch"],
            "receipt_id": r["receipt_id"],
            "decision": validate_decision(parse_json(r["json"])),
        }

    def get_decision_by_binding(self, tenant, gateway, binding_hash):
        r = self._get(
            "SELECT result_id, input_hash, binding_hash, epoch, receipt_id, json FROM decisions "
            "WHERE tenant_id=? AND gateway_id=? AND binding_hash=?",
            tenant, gateway, binding_hash,
        )
        if not r:
            return None
        return {
            "result_id": r["result_id"],
            "input_hash": r["input_hash"],
            "binding_hash": binding_hash,
            "epoch": r["epoch"],
            "receipt_id": r["receipt_id"],
            "decision": validate_decision(parse_json(r["json"])),
        }

    def get_receipt_by_id(self, receipt_id):
        r = self._get("SELECT json FROM receipts WHERE receipt_id=?", receipt_id)
        return validate_signed_receipt(parse_json(r["json"])) if r else None

    def get_chain_head(self, tenant, gateway):
        r = self._get(
            "SELECT seq, hash FROM chain_heads WHERE tenant_id=? AND gateway_id=?",
            tenant, gateway,
        )
        return {"seq": r["seq"], "hash": r["hash"]} if r else None

    def get_receipt_by_seq(self, tenant, gateway, seq):
        r = self._get(
            "SELECT json FROM receipts WHERE tenant_id=? AND gateway_id=? AND seq=?",
            tenant, gateway, seq,
        )
        return validate_signed_receipt(parse_json(r["json"])) if r else None

    def commit(self, tenant, gateway, result_id, input_hash, binding_hash, epoch, build):
        if self.fail_commit:
            raise ClosedError("STORAGE_UNAVAILABLE", "sink unavailable")
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as e:
            raise ClosedError("STORAGE_UNAVAILABLE", f"begin: {e}") from e
        try:
            existing = self.get_decision(tenant, gateway, result_id)
            if existing:
                self.db.execute("ROLLBACK")
                return {"status": "exists", "stored": existing}
            by_binding = self.get_decision_by_binding(tenant, gateway, binding_hash)
            if by_binding and by_binding["result_id"] != result_id:
                self.db.execute("ROLLBACK")
                return {"status": "binding_conflict", "stored": by_binding}
            head_row = self._get(
                "SELECT seq, hash FROM chain_heads WHERE tenant_id=? AND gateway_id=?",
                tenant, gateway,
            )
            seq = head_row["seq"] + 1 if head_row else 1
            prev_hash = head_row["hash"] if head_row else ZERO_HASH
            built = build(seq, prev_hash)
            receipt, decision, quarantine = built["receipt"], built["decision"], built["quarantine"]
            self._run(
                "INSERT INTO receipts(tenant_id,gateway_id,seq,receipt_id,hash,json,recorded_at_ms) "
                "VALUES (?,?,?,?,?,?,?)",
                tenant, gateway, seq, receipt["body"]["receipt_id"], receipt["hash"],
                jcs(receipt), receipt["body"]["recorded_at_ms"],
            )
            self._run(
                "INSERT INTO decisions(tenant_id,gateway_id,result_id,input_hash,epoch,receipt_id,binding_hash,json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                tenant, gateway, result_id, input_hash, epoch,
                receipt["body"]["receipt_id"], binding_hash, jcs(decision),
            )
            if quarantine:
                self._run(
                    "INSERT INTO quarantine(quarantine_id,tenant_id,gateway_id,result_id,receipt_id,expires_at_ms,json) "
                    "VALUES (?,?,?,?,?,?,?)",
                    quarantine["quarantine_id"], tenant, gateway, result_id,
                    receipt["body"]["receipt_id"], quarantine["expires_at_ms"], jcs(quarantine),
                )
            if head_row:
                self._run(
                    "UPDATE chain_heads SET seq=?, hash=? WHERE tenant_id=? AND gateway_id=?",
                    seq, receipt["hash"], tenant, gateway,
                )
            else:
                self._run(
                    "INSERT INTO chain_heads(tenant_id,gateway_id,seq,hash) VALUES (?,?,?,?)",
                    tenant, gateway, seq, receipt["hash"],
                )
            self.db.execute("COMMIT")
            return {"status": "committed", "receipt": receipt}
        except Exception as e:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if isinstance(e, ClosedError):
                raise
            raise ClosedError("STORAGE_UNAVAILABLE", f"commit: {e}") from e

    def put_pack(self, tenant, pack):
        self._run(
            "INSERT OR IGNORE INTO packs(tenant_id,pack_id,serial,hash,json) VALUES (?,?,?,?,?)",
            tenant, pack["body"]["pack_id"], pack["body"]["serial"], pack["hash"], jcs(pack),
        )

    def get_pack(self, tenant, pack_id, serial):
        r = self._get(
            "SELECT hash, json FROM packs WHERE tenant_id=? AND pack_id=? AND serial=?",
            tenant, pack_id, serial,
        )
        if not r:
            return None
        return {
            "tenant_id": tenant, "pack_id": pack_id, "serial": serial,
            "hash": r["hash"], "pack": validate_signed_pack(parse_json(r["json"])),
        }

    def get_pack_by_hash(self, tenant, hash_):
        r = self._get(
            "SELECT pack_id, serial, json FROM packs WHERE tenant_id=? AND hash=?",
            tenant, hash_,
        )
        if not r:
            return None
        return {
            "tenant_id": tenant, "pack_id": r["pack_id"], "serial": r["serial"],
            "hash": hash_, "pack": validate_signed_pack(parse_json(r["json"])),
        }

    def get_max_pack_serial(self, tenant, pack_id):
        r = self._get(
            "SELECT MAX(serial) AS m FROM packs WHERE tenant_id=? AND pack_id=?",
            tenant, pack_id,
        )
        return r["m"] if r and r["m"] is not None else None

    def get_active_snapshot(self, tenant, gateway):
        r = self._get(
            "SELECT json FROM active_snapshot WHERE tenant_id=? AND gateway_id=?",
            tenant, gateway,
        )
        return parse_json(r["json"]) if r else None

    def set_active_snapshot(self, tenant, gateway, rec):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._run(
                "INSERT INTO active_snapshot(tenant_id,gateway_id,epoch,json) VALUES (?,?,?,?) "
                "ON CONFLICT(tenant_id,gateway_id) DO UPDATE SET epoch=excluded.epoch, json=excluded.json",
                tenant, gateway, rec["epoch"], jcs(rec),
            )
            self.db.execute("COMMIT")
        except Exception as e:
            self.db.execute("ROLLBACK")
            raise ClosedError("STORAGE_UNAVAILABLE", f"activate: {e}") from e

    def get_quarantine(self, ident):
        r = self._get("SELECT json FROM quarantine WHERE quarantine_id=?", ident)
        return parse_json(r["json"]) if r else None

    def spool_put(self, row):
        self._run(
            "INSERT OR REPLACE INTO telemetry_spool(batch_id,json,state,attempts,next_attempt_ms,expires_at_ms) "
            "VALUES (?,?,?,?,?,?)",
            row["batch_id"], row["json"], row["state"], row["attempts"],
            row["next_attempt_ms"], row["expires_at_ms"],
        )

    def spool_due(self, now_ms, max_batches):
        rows = self.db.execute(
            "SELECT batch_id,json,state,attempts,next_attempt_ms,expires_at_ms FROM telemetry_spool "
            "WHERE state=? AND next_attempt_ms<=? ORDER BY expires_at_ms ASC LIMIT ?",
            ("pending", now_ms, max_batches),
        ).fetchall()
        return [dict(r) for r in rows]

    def spool_update(self, row):
        self.spool_put(row)

    def spool_count(self):
        r = self._get("SELECT COUNT(*) AS c FROM telemetry_spool")
        return r["c"] if r else 0

    def spool_bytes(self):
        r = self._get("SELECT COALESCE(SUM(LENGTH(json)),0) AS s FROM telemetry_spool")
        return r["s"] if r else 0

    def spool_evict_oldest(self, n):
        rows = self.db.execute(
            "SELECT batch_id FROM telemetry_spool WHERE state=? ORDER BY expires_at_ms ASC LIMIT ?",
            ("pending", n),
        ).fetchall()
        for r in rows:
            self._run("DELETE FROM telemetry_spool WHERE batch_id=?", r["batch_id"])
        return len(rows)

    def receipt_range(self, tenant, gateway, from_seq, to_seq):
        rows = self.db.execute(
            "SELECT json FROM receipts WHERE tenant_id=? AND gateway_id=? AND seq>=? AND seq<=? "
            "ORDER BY seq ASC",
            (tenant, gateway, from_seq, to_seq),
        ).fetchall()
        return [validate_signed_receipt(parse_json(r["json"])) for r in rows]

    def receipt_count(self):
        r = self._get("SELECT COUNT(*) AS c FROM receipts")
        return r["c"] if r else 0

    def verify_tail(self, tenant, gateway, n):
        head = self.get_chain_head(tenant, gateway)
        if not head:
            return True
        last = self.get_receipt_by_seq(tenant, gateway, head["seq"])
        if not last or last["hash"] != head["hash"]:
            return False
        expect_prev = last["body"]["prev_hash"]
        seq = head["seq"]
        checked = 0
        while checked < n and seq > 1:
            prev = self.get_receipt_by_seq(tenant, gateway, seq - 1)
            if not prev or prev["hash"] != expect_prev:
                return False
            expect_prev = prev["body"]["prev_hash"]
            seq -= 1
            checked += 1
        if seq == 1 and expect_prev != ZERO_HASH:
            return False
        return True
