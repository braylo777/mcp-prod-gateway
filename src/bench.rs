//! Per-check latency over the whole corpus (simple wall-clock timing, no criterion).
//!
//! Each tool in the attack and benign corpora is checked once per round, timed per call with
//! `Instant`. Percentiles are over all calls. Build with `--release` for meaningful numbers.

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use serde::Serialize;
use serde_json::Value;

use crate::corpus::{Attack, Manifest, EXTERNAL};
use crate::scanner::{diff_against_approved, fingerprint, scan_poisoning, scan_scopes};
use crate::{http, policy};

#[derive(Debug, Serialize, Clone)]
pub struct Stat {
    pub calls: usize,
    pub p50_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
}

pub fn stat(mut ns: Vec<u128>) -> Stat {
    if ns.is_empty() {
        return Stat { calls: 0, p50_us: 0.0, p99_us: 0.0, max_us: 0.0 };
    }
    ns.sort_unstable();
    let q = |p: f64| ns[((ns.len() as f64 - 1.0) * p).round() as usize] as f64 / 1000.0;
    Stat { calls: ns.len(), p50_us: q(0.50), p99_us: q(0.99), max_us: *ns.last().unwrap() as f64 / 1000.0 }
}

fn time<F: FnMut()>(out: &mut Vec<u128>, mut f: F) {
    let t = Instant::now();
    f();
    out.push(t.elapsed().as_nanos());
}

/// Returns check name -> stats. `rounds` repeats the corpus (1 is enough for p99).
pub fn run(attacks: &[Attack], benign: &[Manifest], rounds: usize) -> BTreeMap<String, Stat> {
    let ext: HashSet<String> = EXTERNAL.iter().map(|s| s.to_string()).collect();
    let mut items: Vec<(Value, HashSet<String>, Vec<String>)> = vec![];
    for a in attacks {
        items.push((a.tool.clone(), a.siblings.iter().cloned().collect(), a.scopes.clone()));
    }
    for m in benign {
        let names: HashSet<String> = m.tools.iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        for t in &m.tools {
            let n = t["name"].as_str().unwrap();
            let mut sib = names.clone();
            sib.remove(n);
            items.push((t.clone(), sib, m.scopes.get(n).cloned().unwrap_or_default()));
        }
    }
    let rugs: Vec<(Value, BTreeMap<String, String>)> = attacks
        .iter()
        .filter_map(|a| a.approved.as_ref().map(|p| (a.tool.clone(), BTreeMap::from([(p["name"].as_str().unwrap().to_string(), fingerprint(p))]))))
        .collect();
    let reqs: Vec<Vec<u8>> = items
        .iter()
        .take(500)
        .map(|(t, _, _)| {
            let body = serde_json::to_vec(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": t["name"], "arguments": {}}})).unwrap();
            let mut r = format!("POST / HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            r.extend(body);
            r
        })
        .collect();

    // warm-up: compile lazy regexes
    for (t, sib, sc) in items.iter().take(50) {
        let _ = policy::scan_tool(t, sib, &ext, sc);
    }
    let (mut v1p, mut v1s, mut deep, mut fp, mut full, mut diff, mut parse) = (vec![], vec![], vec![], vec![], vec![], vec![], vec![]);
    for _ in 0..rounds {
        for (t, sib, sc) in &items {
            let mut known: HashSet<String> = sib.union(&ext).cloned().collect();
            known.insert(t["name"].as_str().unwrap_or("?").into());
            time(&mut v1p, || {
                std::hint::black_box(scan_poisoning(t, &known));
            });
            time(&mut v1s, || {
                std::hint::black_box(scan_scopes(t, sc));
            });
            time(&mut deep, || {
                std::hint::black_box(policy::scan_deep(t, &ext));
            });
            time(&mut fp, || {
                std::hint::black_box(fingerprint(t));
            });
            time(&mut full, || {
                std::hint::black_box(policy::scan_tool(t, sib, &ext, sc));
            });
        }
        for (t, ap) in &rugs {
            time(&mut diff, || {
                std::hint::black_box(diff_against_approved(std::slice::from_ref(t), ap));
            });
        }
        for r in &reqs {
            time(&mut parse, || {
                std::hint::black_box(http::parse_request(r).unwrap());
            });
        }
    }
    BTreeMap::from([
        ("v1_poisoning".into(), stat(v1p)),
        ("v1_scopes".into(), stat(v1s)),
        ("deep_rules".into(), stat(deep)),
        ("fingerprint".into(), stat(fp)),
        ("full_scan_tool".into(), stat(full)),
        ("rug_pull_diff".into(), stat(diff)),
        ("http_parse".into(), stat(parse)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_percentiles() {
        let s = stat((1..=100).map(|x| x * 1000).collect());
        assert_eq!((s.calls, s.p50_us, s.p99_us, s.max_us), (100, 51.0, 99.0, 100.0));
    }

    #[test]
    fn run_small_corpus_under_target() {
        let a = crate::corpus::attacks();
        let b = crate::corpus::benign();
        let r = run(&a[..80], &b[..40], 1);
        assert_eq!(r.len(), 7);
        assert!(r["full_scan_tool"].calls > 0);
        assert_eq!(stat(vec![]).calls, 0);
        // generous bound for debug builds; the release target is p99 < 1 ms
        assert!(r["http_parse"].p99_us < 5_000.0);
    }
}
