"""Section 10.1: persistence contract. One immediate transaction checks
uniqueness, allocates seq, constructs/signs the receipt, inserts
decision/quarantine, and advances the head. No raw input, sanitized
content, model features, credential strings, or private signing keys are
persisted.
"""

from .errors import ClosedError
from .jcs import parse_json
from .schema import validate_decision, validate_signed_receipt

ZERO_HASH = "0" * 64


class MemorySink:
    """In-memory sink: same semantics as the SQLite sink, used by the
    conformance harness and embedders that provide their own storage."""

    def __init__(self):
        self.decisions = {}
        self.receipts = {}
        self.receipts_by_seq = {}
        self.heads = {}
        self.packs = {}
        self.active = {}
        self.quarantine = {}
        self.spool = {}
        # failure injection for fault-matrix tests
        self.fail_commit = False

    @staticmethod
    def _kg(t, g):
        return f"{t}/{g}"

    def open(self):
        pass

    def close(self):
        pass

    def get_decision(self, tenant, gateway, result_id):
        return self.decisions.get(f"{tenant}/{gateway}/{result_id}")

    def get_decision_by_binding(self, tenant, gateway, binding_hash):
        k = f"{tenant}/{gateway}"
        for d in self.decisions.values():
            if d["binding_hash"] == binding_hash and self.decisions.get(f"{k}/{d['result_id']}") is d:
                return d
        return None

    def get_receipt_by_id(self, receipt_id):
        return self.receipts.get(receipt_id)

    def get_chain_head(self, tenant, gateway):
        return self.heads.get(self._kg(tenant, gateway))

    def get_receipt_by_seq(self, tenant, gateway, seq):
        return self.receipts_by_seq.get(f"{tenant}/{gateway}/{seq}")

    def commit(self, tenant, gateway, result_id, input_hash, binding_hash, epoch, build):
        if self.fail_commit:
            raise ClosedError("STORAGE_UNAVAILABLE", "sink unavailable")
        dk = f"{tenant}/{gateway}/{result_id}"
        existing = self.decisions.get(dk)
        if existing:
            return {"status": "exists", "stored": existing}
        by_binding = self.get_decision_by_binding(tenant, gateway, binding_hash)
        if by_binding and by_binding["result_id"] != result_id:
            return {"status": "binding_conflict", "stored": by_binding}
        head = self.heads.get(self._kg(tenant, gateway), {"seq": 0, "hash": ZERO_HASH})
        seq = head["seq"] + 1
        built = build(seq, head["hash"])
        receipt, decision, quarantine = built["receipt"], built["decision"], built["quarantine"]
        self.receipts[receipt["body"]["receipt_id"]] = receipt
        self.receipts_by_seq[f"{tenant}/{gateway}/{seq}"] = receipt
        self.heads[self._kg(tenant, gateway)] = {"seq": seq, "hash": receipt["hash"]}
        self.decisions[dk] = {
            "result_id": result_id,
            "input_hash": input_hash,
            "binding_hash": binding_hash,
            "epoch": epoch,
            "receipt_id": receipt["body"]["receipt_id"],
            "decision": decision,
        }
        if quarantine:
            self.quarantine[quarantine["quarantine_id"]] = quarantine
        return {"status": "committed", "receipt": receipt}

    def put_pack(self, tenant, pack):
        self.packs[f"{tenant}/{pack['body']['pack_id']}/{pack['body']['serial']}"] = {
            "tenant_id": tenant,
            "pack_id": pack["body"]["pack_id"],
            "serial": pack["body"]["serial"],
            "hash": pack["hash"],
            "pack": pack,
        }

    def get_pack(self, tenant, pack_id, serial):
        return self.packs.get(f"{tenant}/{pack_id}/{serial}")

    def get_pack_by_hash(self, tenant, hash_):
        for p in self.packs.values():
            if p["tenant_id"] == tenant and p["hash"] == hash_:
                return p
        return None

    def get_max_pack_serial(self, tenant, pack_id):
        m = None
        for p in self.packs.values():
            if p["tenant_id"] == tenant and p["pack_id"] == pack_id:
                if m is None or p["serial"] > m:
                    m = p["serial"]
        return m

    def get_active_snapshot(self, tenant, gateway):
        return self.active.get(self._kg(tenant, gateway))

    def set_active_snapshot(self, tenant, gateway, rec):
        self.active[self._kg(tenant, gateway)] = rec

    def get_quarantine(self, ident):
        return self.quarantine.get(ident)

    def spool_put(self, row):
        self.spool[row["batch_id"]] = row

    def spool_due(self, now_ms, max_batches):
        due = [
            r
            for r in self.spool.values()
            if r["state"] == "pending" and r["next_attempt_ms"] <= now_ms
        ]
        due.sort(key=lambda r: r["expires_at_ms"])
        return due[:max_batches]

    def spool_update(self, row):
        self.spool[row["batch_id"]] = row

    def spool_count(self):
        return len(self.spool)

    def spool_bytes(self):
        return sum(len(r["json"]) for r in self.spool.values())

    def spool_evict_oldest(self, n):
        pending = [r for r in self.spool.values() if r["state"] == "pending"]
        pending.sort(key=lambda r: r["expires_at_ms"])
        evicted = 0
        for r in pending[:n]:
            del self.spool[r["batch_id"]]
            evicted += 1
        return evicted

    def receipt_range(self, tenant, gateway, from_seq, to_seq):
        out = []
        for s in range(from_seq, to_seq + 1):
            r = self.receipts_by_seq.get(f"{tenant}/{gateway}/{s}")
            if not r:
                break
            out.append(r)
        return out

    def receipt_count(self):
        return len(self.receipts)

    def verify_tail(self, tenant, gateway, n):
        head = self.heads.get(self._kg(tenant, gateway))
        if not head:
            return True
        last = self.receipts_by_seq.get(f"{tenant}/{gateway}/{head['seq']}")
        if not last or last["hash"] != head["hash"]:
            return False
        seq = head["seq"]
        expect_prev = last["body"]["prev_hash"]
        checked = 0
        while checked < n and seq > 1:
            prev = self.receipts_by_seq.get(f"{tenant}/{gateway}/{seq - 1}")
            if not prev or prev["hash"] != expect_prev:
                return False
            expect_prev = prev["body"]["prev_hash"]
            seq -= 1
            checked += 1
        if seq == 1 and expect_prev != ZERO_HASH:
            return False
        return True


# Re-validate stored rows defensively (they were validated at insert time).
def parse_stored_decision(json_str):
    return validate_decision(parse_json(json_str))


def parse_stored_receipt(json_str):
    return validate_signed_receipt(parse_json(json_str))
