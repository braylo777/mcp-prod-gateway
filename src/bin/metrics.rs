//! `cargo run --bin metrics [-- --no-coverage]`: measure everything and write `metrics.json`.
//!
//! Runs the corpus eval in-process, counts parity against the Python fixtures, runs
//! `cargo test --release` and the Python reference tests, the release latency bench and
//! `cargo llvm-cov` (line coverage of the library). Honors `CARGO_TARGET_DIR`.

use std::path::Path;
use std::process::Command;

use mcpgw::{corpus, eval, parity};
use serde_json::{json, Value};

fn run(cmd: &str, args: &[&str], dir: &Path) -> (bool, String) {
    match Command::new(cmd).args(args).current_dir(dir).output() {
        Ok(o) => (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
        Err(e) => (false, e.to_string()),
    }
}

/// Sum "test result: ok. N passed; M failed" lines.
fn cargo_counts(out: &str) -> (usize, usize) {
    let (mut p, mut f) = (0, 0);
    for l in out.lines().filter(|l| l.contains("test result:")) {
        let num = |key: &str| l.split(';').find(|s| s.contains(key)).and_then(|s| s.split_whitespace().rev().nth(1)?.parse::<usize>().ok()).unwrap_or(0);
        p += num(" passed");
        f += num(" failed");
    }
    (p, f)
}

fn pytest_counts(out: &str) -> (usize, usize) {
    let last = out.lines().rev().find(|l| l.contains(" passed") || l.contains(" failed")).unwrap_or("");
    let num = |key: &str| {
        let w: Vec<&str> = last.split([',', ' ']).filter(|s| !s.is_empty()).collect();
        w.iter().position(|s| s.starts_with(key)).and_then(|i| w.get(i.wrapping_sub(1))?.parse::<usize>().ok()).unwrap_or(0)
    };
    (num("passed"), num("failed"))
}

fn loc(dir: &Path, ext: &str) -> usize {
    let mut n = 0;
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if !name.starts_with('.') && name != "target" && name != "fixtures" && name != "__pycache__" {
                n += loc(&p, ext);
            }
        } else if p.extension().is_some_and(|x| x == ext) {
            let comment = if ext == "rs" { "//" } else { "#" };
            n += std::fs::read_to_string(&p).unwrap_or_default().lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(comment)).count();
        }
    }
    n
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let skip_cov = std::env::args().any(|a| a == "--no-coverage");

    let attacks: Vec<corpus::Attack> = corpus::from_jsonl(&std::fs::read_to_string(root.join("corpus/attacks.jsonl")).unwrap());
    let benign: Vec<corpus::Manifest> = corpus::from_jsonl(&std::fs::read_to_string(root.join("corpus/benign.jsonl")).unwrap());
    let r = eval::run(&attacks, &benign);
    eprintln!("eval: caught {}/{} · fp {}/{}", r.caught, r.attacks, r.fp_manifests, r.manifests);

    let (s_ok, s_n) = parity::scanner(root);
    let (c_ok, c_n) = parity::core(root);
    eprintln!("parity: scanner {s_ok}/{s_n} · core {c_ok}/{c_n}");

    eprintln!("running cargo test --release ...");
    let (_, out) = run("cargo", &["test", "--release", "--quiet"], root);
    let (rp, rf) = cargo_counts(&out);
    let (_, pout) = run("python3", &["-m", "pytest", "-q", "reference/tests"], root);
    let (pp, pf) = pytest_counts(&pout);
    eprintln!("tests: rust {rp} passed / {rf} failed · python {pp} passed / {pf} failed");

    eprintln!("running release bench ...");
    let (_, bout) = run("cargo", &["run", "--release", "--quiet", "--bin", "bench", "--", "3", "--json"], root);
    let bench: Value = bout.lines().rev().find_map(|l| serde_json::from_str(l).ok()).unwrap_or(json!({}));
    let p99_us = bench.as_object().map(|o| o.values().filter_map(|s| s["p99_us"].as_f64()).fold(0.0, f64::max)).unwrap_or(f64::NAN);

    let coverage = if skip_cov {
        Value::Null
    } else {
        eprintln!("running cargo llvm-cov (slow) ...");
        let (ok, tout) = run("cargo", &["llvm-cov", "--release", "--no-report"], root);
        if !ok {
            eprintln!("llvm-cov test run failed:\n{}", tout.lines().rev().take(20).collect::<Vec<_>>().join("\n"));
        }
        let (_, cout) = run("cargo", &["llvm-cov", "report", "--release", "--summary-only", "--json", "--ignore-filename-regex", "src/bin/"], root);
        cout.lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l).ok())
            .and_then(|v| v["data"][0]["totals"]["lines"]["percent"].as_f64())
            .map(|p| json!((p * 10.0).round() / 10.0))
            .unwrap_or(Value::Null)
    };

    let m = json!({
        "caught": r.caught,
        "attacks": r.attacks,
        "recall": (r.recall() * 1000.0).round() / 1000.0,
        "per_family": r.per_family.iter().map(|(k, (c, t))| (k.clone(), json!(format!("{c}/{t}")))).collect::<serde_json::Map<_, _>>(),
        "benign_manifests": r.manifests,
        "benign_tools": r.benign_tools,
        "fp_manifests": r.fp_manifests,
        "fp_rate": r.fp_rate(),
        "scope_advisory_manifests": r.scope_advisory_manifests,
        "rust_parity": format!("{}/{}", s_ok + c_ok, s_n + c_n),
        "rust_parity_scanner": format!("{s_ok}/{s_n}"),
        "rust_parity_core": format!("{c_ok}/{c_n}"),
        "tests": rp + rf + pp + pf,
        "tests_passing": rp + pp,
        "tests_rust": rp + rf,
        "tests_python_reference": pp + pf,
        "loc_rust": loc(&root.join("src"), "rs") + loc(&root.join("tests"), "rs"),
        "loc_python": loc(&root.join("reference"), "py") + loc(&root.join("analysis"), "py"),
        "p99_ms": (p99_us / 1000.0 * 1000.0).round() / 1000.0,
        "p99_ms_by_check": bench.as_object().map(|o| o.iter().map(|(k, s)| (k.clone(), json!((s["p99_us"].as_f64().unwrap_or(0.0)).round() / 1000.0))).collect::<serde_json::Map<_, _>>()),
        "coverage": coverage,
    });
    let text = serde_json::to_string_pretty(&m).unwrap() + "\n";
    std::fs::write(root.join("metrics.json"), &text).unwrap();
    print!("{text}");
}
