# Changelog

## 0.2.0 — 2026-11-20
### Added
- Attack corpus: 690 generated cases in 11 families (`corpus/attacks.jsonl`, `src/corpus.rs`). Templates × mutations × carriers, fixed seed.
- Benign corpus: 1,000 synthesized manifests, 2,398 tools, 25 archetypes (`corpus/benign.jsonl`).
- Policy layer (`src/policy.rs`): text normalization plus rules TP009–TP016, SH001, SH002.
- Policy refinements: same-server reference without a hook → low; TP003 benign handling note → low; TP006 needs verb and sink in one sentence.
- Rust HTTP/1.1 binding (`src/http.rs`): strict parser, server thread, client. Replaces `mcpgw/http.py`.
- Parity fixtures from the Python reference: 3,158 corpus cases and 612 core cases (canon, PKCE, JWT, negotiation, shims, schema subset).
- Latency bench (`cargo run --release --bin bench`); worst per-check p99 0.11–0.17 ms.
- proptest fuzzing of the HTTP parser, scanners, canon JSON, JWT and fingerprints (`tests/fuzz.rs`).
- `cargo run --bin metrics` writes `metrics.json`.
- CI: debug + release tests, corpus freshness, fuzz, bench, clippy, coverage, Python reference + fixture freshness.

### Changed
- The Rust crate moved to the repo root. Python moved to `reference/` (frozen oracle) and `analysis/` (scripts).
- The gateway approves and rechecks servers with the policy layer. Other servers' tools are the shadowing context.
- TP005 name regexes are cached per thread (full-scan p99 242 → 114 µs).

### Fixed
- `canon`: floats now follow Python `repr` (`1e-07`, `1e+300`). Found by parity fixtures.
- `serde_json` float parsing was off by one ulp; enabled `float_roundtrip`. Found by fuzzing.
- Corpus soft-hyphen mutation split inside a UTF-8 character. Found by fuzzing.

### Results
- Caught 650/690; all 40 misses are the held-out paraphrase family (0/40).
- False positives 0/1,000 manifests (54/1,000 with the v1 rules alone).
- Parity 3,818/3,818. Tests 345 (322 Rust + 23 Python), all passing.

## 0.1.0
- Python gateway (OAuth 2.1, version shims, allowlist, scanner) and a Rust port with 48/48 scanner parity.
