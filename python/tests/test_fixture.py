"""Golden anchors from section 19/4.4: the printed S0 values must match the
implementation byte-for-byte — these pin JCS, hashing domains, Ed25519,
the ID allocator, and the full screen path.
"""

import copy

from lexsieve.crypto import ed25519_public_from_seed
from lexsieve.eval.clocks import fake_clock
from lexsieve.eval.fixture19 import (
    C0, CM0, H, H0, I, J, M0, P0, PH0, Q0, R0, S0, T0, gen_receipt,
    letter_allocator, pub, seed,
)
from lexsieve.engine import Engine
from lexsieve.jcs import jcs
from lexsieve.lexshield import STATIC_POLICY_HASH, StaticLexShield
from lexsieve.packs import activate_pack, config_hash_of
from lexsieve.sink import MemorySink
from lexsieve.sqlite import SqliteSink
from lexsieve.verify import replay


def build_runtime_for_test(profile, sink=None):
    config = CM0 if profile == "M" else C0
    s = sink or MemorySink()
    clock = fake_clock(1000)
    s.open()
    activate_pack(s, config, T0, P0, clock.now(), config_hash_of(config), STATIC_POLICY_HASH)
    deps = {
        "sink": s,
        "clock": clock,
        "ids": letter_allocator(),
        "lexshield": StaticLexShield(),
        "signer": {"key_id": I("lskey", "B"), "seed": seed},
    }
    return {"engine": Engine(config, deps), "sink": s, "clock": clock}


def test_rfc8032_key_derivation_matches_fixture_public_key():
    assert pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_static_policy_hash_matches_h0():
    assert STATIC_POLICY_HASH == "16a9ed3d0a547b3103e7d01ea797797422f0b396790ab7ea6a93ad8e1895e801"


def test_p0_pack_hash_matches_ph0_printed_value():
    assert P0["hash"] == "1adeb52efeda50e1586f25e1adf064430ca5c748440fb3ecd7e5adad0b4e76fb"


def test_c0_config_hash_matches_printed_value():
    assert H(J(C0)) == "a1e7eb529ce214bb40165df566124e7c373b16c6995ea384a668a94d5504df2f"


def test_r0_receipt_hash_and_signature_match_printed_fixture():
    assert R0["hash"] == "e1ff9ff88352f3a6d74d406f2cd1172349224c7e51b50a1cddccc5ee2c014bb2"
    assert (
        R0["signature"]
        == "8ldHhAWXawJLPwpoMZDEDO_znflMlx6Sk--1GA0MTr8Qa9Xj68QF8UFGvP45TMUjQwMNm0uuY3jauDQgUlpbBw"
    )


def test_screen_q0_under_fixture_runtime_produces_s0_exactly():
    rt = build_runtime_for_test("R")
    resp = rt["engine"].screen(copy.deepcopy(Q0))
    assert jcs(resp) == jcs(S0)
    assert resp["decision"]["input_hash"] == "58eafc3a1193bc0e7a2258644a862514d9cc2af5a1028507f2a987c6263307bb"
    assert resp["decision"]["output_hash"] == "1fef99be7abd8612d8cf4b2b66d7859fff029167850484206bb3b243f3d5d38f"


def test_replay_of_recorded_s0_is_equal():
    rt = build_runtime_for_test("R")
    resp = rt["engine"].screen(copy.deepcopy(Q0))
    r = replay(rt["engine"], {"v": 1, "request": Q0, "recorded": resp})
    assert r == {"v": 1, "equal": True, "differences": []}


def test_sqlite_sink_round_trips_commits_and_chain_verification():
    sink = SqliteSink(":memory:")
    rt = build_runtime_for_test("R", sink)
    resp = rt["engine"].screen(copy.deepcopy(Q0))
    assert resp["decision"]["verdict"] == "pass"
    assert sink.receipt_count() == 1
    assert sink.verify_tail(C0["tenant_id"], C0["gateway_id"], 10) is True
    stored = sink.get_receipt_by_seq(C0["tenant_id"], C0["gateway_id"], 1)
    assert stored["hash"] == R0["hash"]
    sink.close()


def test_memory_and_sqlite_sinks_produce_identical_committed_objects():
    a = build_runtime_for_test("R", MemorySink())
    b = build_runtime_for_test("R", SqliteSink(":memory:"))
    ra = a["engine"].screen(copy.deepcopy(Q0))
    rb = b["engine"].screen(copy.deepcopy(Q0))
    assert jcs(ra) == jcs(rb)


def test_replay_reports_a_tampered_input():
    rt = build_runtime_for_test("R")
    resp = rt["engine"].screen(copy.deepcopy(Q0))
    tampered = copy.deepcopy(Q0)
    tampered["candidate"]["tool_error"] = True
    r = replay(rt["engine"], {"v": 1, "request": tampered, "recorded": resp})
    assert r["equal"] is False
    assert "input" in r["differences"]
