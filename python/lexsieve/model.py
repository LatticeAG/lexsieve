"""Section 6.3: lexsieve.linear.v1 — local, signed, sparse integer linear
classifier over word 1-, 2-, and 3-grams. Deterministic integer arithmetic;
no tools, no network, no floating point.
"""

from .errors import ClosedError
from .jcs import is_obj, jcs
from .crypto import sha256_hex
from .unicode import is_token_char

MODEL_CLASSES = ["override", "exfiltration", "tool_directive"]

_INT16_MIN, _INT16_MAX = -32768, 32767


def _is_int16(n):
    return isinstance(n, int) and not isinstance(n, bool) and _INT16_MIN <= n <= _INT16_MAX


def _utf8_sorted_unique(arr):
    prev = None
    for s in arr:
        b = s.encode("utf-8")
        if prev is not None and prev >= b:
            return False
        prev = b
    return True


def validate_model_artifact(v):
    """Validates a decoded JSON value as a ModelArtifact. The weights array
    must already be in ascending UTF-8 byte order with no duplicates;
    violations fail schema validation."""
    if not is_obj(v):
        raise ClosedError("INVALID_REQUEST", "model not object")
    o = v
    if sorted(o.keys()) != ["bias", "classes", "format", "threshold", "tokenizer", "unicode", "weights"]:
        raise ClosedError("INVALID_REQUEST", "model members")
    if o["format"] != "lexsieve.linear.v1":
        raise ClosedError("INVALID_REQUEST", "model format")
    if o["unicode"] != "15.1.0":
        raise ClosedError("INVALID_REQUEST", "model unicode")
    if o["tokenizer"] != "word-ngram-1-3-v1":
        raise ClosedError("INVALID_REQUEST", "model tokenizer")
    if not isinstance(o["classes"], list) or o["classes"] != MODEL_CLASSES:
        raise ClosedError("INVALID_REQUEST", "model classes")
    if not isinstance(o["bias"], list) or len(o["bias"]) != 3 or not all(_is_int16(x) for x in o["bias"]):
        raise ClosedError("INVALID_REQUEST", "model bias")
    if not _is_int16(o["threshold"]):
        raise ClosedError("INVALID_REQUEST", "model threshold")
    if not isinstance(o["weights"], list) or len(o["weights"]) > 4096:
        raise ClosedError("INVALID_REQUEST", "model weights bound")
    features = []
    weights = []
    for w in o["weights"]:
        if not is_obj(w):
            raise ClosedError("INVALID_REQUEST", "weight not object")
        if sorted(w.keys()) != ["feature", "values"]:
            raise ClosedError("INVALID_REQUEST", "weight members")
        if not isinstance(w["feature"], str) or len(w["feature"].encode("utf-8")) > 192:
            raise ClosedError("INVALID_REQUEST", "feature size")
        if not isinstance(w["values"], list) or len(w["values"]) != 3 or not all(_is_int16(x) for x in w["values"]):
            raise ClosedError("INVALID_REQUEST", "weight values")
        features.append(w["feature"])
        weights.append({"feature": w["feature"], "values": w["values"]})
    if not _utf8_sorted_unique(features):
        raise ClosedError("INVALID_REQUEST", "weights not sorted/unique")
    return {
        "format": "lexsieve.linear.v1",
        "unicode": "15.1.0",
        "tokenizer": "word-ngram-1-3-v1",
        "classes": list(MODEL_CLASSES),
        "bias": o["bias"],
        "threshold": o["threshold"],
        "weights": weights,
    }


def model_hash(m):
    return sha256_hex(jcs(m))


def featurize(views):
    """Tokenize one normalized view into maximal
    Letter/Number/Connector_Punctuation sequences, then emit the set union
    of 1/2/3-grams (tokens joined by one ASCII space). Features over 192
    UTF-8 bytes are omitted."""
    features = set()
    for view in views:
        tokens = []
        cur = []
        for c in view:
            if is_token_char(c.cp):
                cur.append(c.cp)
            elif cur:
                tokens.append("".join(chr(x) for x in cur))
                cur = []
        if cur:
            tokens.append("".join(chr(x) for x in cur))
        for i in range(len(tokens)):
            gram = tokens[i]
            if len(gram.encode("utf-8")) <= 192:
                features.add(gram)
            for w in (2, 3):
                if i + w > len(tokens):
                    break
                gram = gram + " " + tokens[i + w - 1]
                if len(gram.encode("utf-8")) <= 192:
                    features.add(gram)
    return features


def score(artifact, features):
    """score(ModelRequest) -> ModelResponse: pure function over a validated
    artifact. `features` must be unique and ascending UTF-8 sorted, capped
    at 32768."""
    if len(features) > 32768:
        raise ClosedError("INVALID_REQUEST", "feature cap")
    if not _utf8_sorted_unique(features):
        raise ClosedError("INVALID_REQUEST", "features not sorted")
    present = set(features)
    scores = list(artifact["bias"])
    for w in artifact["weights"]:
        if w["feature"] not in present:
            continue
        for c in range(3):
            s = scores[c] + w["values"][c]
            if s > 2147483647 or s < -2147483648:
                raise ClosedError("INTERNAL", "score overflow")
            scores[c] = s
    positive = [MODEL_CLASSES[c] for c in range(3) if scores[c] >= artifact["threshold"]]
    return {
        "v": 1,
        "model_hash": model_hash(artifact),
        "scores": scores,
        "positive": positive,
    }
