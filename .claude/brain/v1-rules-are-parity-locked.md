# v1 rules are parity-locked; new detection goes in policy.rs

`src/scanner.rs` must stay identical to `reference/mcpgw/scanner.py` (3,206 fixture cases).
- Do not change v1 regexes or findings. Put new rules and severity refinements in `src/policy.rs`.
- If you must change v1, change the Python too, then run `python3 analysis/gen_parity.py`.
- After any corpus generator change: `cargo run --release --bin gen-corpus`, then regenerate both parity fixtures.
- Build with `CARGO_TARGET_DIR=$HOME/.cache/mlg-target`. The $BRAY exFAT drive uses 1 MB clusters and filled up once.
- The holdout_paraphrase family (0/40) is deliberate. Do not tune rules to it; it measures the regex limit.
