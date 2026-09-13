# LexSieve

[![CI](https://github.com/LatticeAG/lexsieve/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/lexsieve/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-1-informational.svg)](#conformance)
[![Node](https://img.shields.io/badge/node-%E2%89%A522.13-339933.svg)](https://nodejs.org)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.12-3776AB.svg)](https://python.org)

**LexSieve** is a deterministic security boundary on the tool-result return
path. It sits between a tool and the model: every tool result is screened
before it can enter model context, so planted instructions, credential-
exfiltration prompts, unauthorized action directives, and cross-call
concatenation tricks are stripped or quarantined — never concatenated,
never trusted, never silently dropped.

Both implementations share one protocol: identical wire schemas, canonical
JSON (RFC 8785), pinned Unicode 15.1 semantics, identical decisions, spans,
hashes, and Ed25519 signatures.

- **TypeScript** (`src/`, `bin/lexsieve.js`) — Node ≥ 22.13, zero runtime
  dependencies.
- **Python** (`python/lexsieve`, `python -m lexsieve`) — Python ≥ 3.12,
  `cryptography` for Ed25519.

## Install & test

```bash
npm ci            # dev deps only; runtime has none
npm test          # node:test — 60/60 conformance vectors + anchors
npm run eval      # locked corpus: fixtures/conformance, manifest-pinned
npm run build     # tsc -> dist/

cd python
python -m pytest -q        # same 60 vectors + golden anchors
python -m lexsieve --help  # same CLI as bin/lexsieve.js
```

## Quick start

```bash
# 1. keys (receipt signing + pack signing)
lexsieve keygen

# 2. compile and sign a rules pack
lexsieve pack compile --input pack-body.json --output pack-body.jcs
lexsieve pack sign --input pack-body.jcs --key-id lskey_… \
  --seed-env LEXSIEVE_PACK_SEED --output packs/active.json

# 3. verify deployment config
lexsieve check-config --config lexsieve.json

# 4. screen a tool result (stdin or file; exits 0/10/20 = pass/strip/hold)
lexsieve scan --input request.json --config lexsieve.json --output resp.json
```

A `ScreenRequest` carries a `candidate` — result ID, binding (tenant,
gateway, run, call, tool, adapter), `tool_error`, and ordered text blocks.
The response is a `decision` (verdict, reason, findings, replacements, input
and output hashes, signed policy snapshot), the model-facing `envelope`
(`trust: "untrusted"`, provenance hash, sanitized blocks), and a hash-chained
Ed25519 `receipt`.

## What it catches

Deterministic baseline classes, in order: `override` (instruction
overrides), `exfiltration` (secret upload/send phrasing), `tool_directive`
("run this command", "invoke the payment tool"), `role_spoof`
(`<|system|>`, `<|im_start|>system`, `[system]`), `encoding` (base64/hex
runs that decode to instructions), `credential` (`Authorization: Bearer`,
private-key blocks). Rule packs add signed, versioned literals; `required`
mode adds a local sparse integer linear classifier over word 1–3-grams.

Findings map back to exact UTF-8 byte spans and are replaced by
`[lexsieve:removed]`; spans that can't be closed safely escalate to a hold.
Holds emit an empty envelope with notice `Tool result withheld by LexSieve.` —
raw tool bytes never appear in failures, diagnostics, or the audit store.

## CLI surface

```
check-config --config P
scan --input -|P --config P [--output P] [--replace]
pack compile --input P --output P
pack sign --input P --key-id K --seed-env E --output P
pack verify --input P --trust T --now-ms N
pack pull  …            # hosted: explicit NotImplemented boundary
keygen
reload --config P       # owner-only unix control socket
audit verify --input P --trust T --anchor-seq N --anchor-hash H
audit export --config P --from-seq A --to-seq B --output P
replay --input P [--config P]
eval --suite S --fixtures D --seed N --report P
telemetry flush --config P --max-batches N
```

Exit codes: `0` ok · `10` strip · `20` hold · `2` usage/schema ·
`3` config/not-ready · `4` I/O · `5` verification · `6` auth ·
`7` retryable network · `8` eval/replay.

## Conformance

`fixtures/conformance/vectors.json` locks vectors `TV-L--01..60` behind a
SHA-256 manifest. The suite covers screening, adapters (native / MCP /
OpenAI), lifecycle, idempotent retries, pack trust windows and monotonic
serials, receipt chains, telemetry ingest, schema strictness, and the
180 ms stage budget. `npm run eval` and `python -m lexsieve eval` both
report `{"passed":60,"failed":0}`.

## Scope

This repo is the MIT-licensed **OSS core**: screening engine, sinks
(in-memory + SQLite), signed packs, receipt verification, replay, adapters,
CLI, conformance harness. Hosted/cloud surfaces (managed control plane,
hosted telemetry ingest, pack pull) are explicit `NotImplemented`
boundaries — no fake working code.

## License

MIT — see [LICENSE](LICENSE).
