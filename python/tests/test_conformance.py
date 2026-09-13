"""Section 20 conformance suite: all 60 TV-L vectors run through the
integration harness. Expected is compared structurally with no ignored
members; unknown ops/fields/IDs are harness failures.
"""

import json
from pathlib import Path

import pytest

from lexsieve.eval.harness import run_vector
from lexsieve.jcs import jcs

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
CORPUS = json.loads((FIXTURES / "conformance" / "vectors.json").read_text("utf-8"))
VECTORS = CORPUS["vectors"]

EXPECTED_IDS = [f"TV-L--{i + 1:02d}" for i in range(60)]


def test_vector_id_set_is_exactly_tv_l_01_to_60():
    assert [v["id"] for v in VECTORS] == EXPECTED_IDS


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vector):
    actual = run_vector(vector)
    for k in vector["expected"]:
        assert k in actual, f"missing output member {k}; actual={json.dumps(actual)}"
    for k in actual:
        assert k in vector["expected"], f"unexpected output member {k}={json.dumps(actual[k])}"
    assert jcs(actual) == jcs(vector["expected"]), (
        f"expected {json.dumps(vector['expected'])}\nactual   {json.dumps(actual)}"
    )
