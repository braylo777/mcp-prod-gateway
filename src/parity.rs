//! Parity counters used by the `metrics` bin: compare the Rust port with the Python reference
//! fixtures in `tests/fixtures/` (read at runtime from the repo root).

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;

use crate::corpus::{self, Attack, Manifest, EXTERNAL};
use crate::scanner::{fingerprint, scan_poisoning, scan_scopes};
use crate::{canon, oauth, versions};

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn rust_findings(tool: &Value, known: &HashSet<String>, scopes: &[String], with_tool: bool) -> Vec<Vec<String>> {
    let mut f: Vec<Vec<String>> = scan_poisoning(tool, known)
        .into_iter()
        .chain(scan_scopes(tool, scopes))
        .map(|f| if with_tool { vec![f.rule, f.severity, f.tool, f.detail] } else { vec![f.rule, f.severity, f.detail] })
        .collect();
    f.sort();
    f
}

/// (matched, total) over `parity.json` (48) and `parity_corpus.jsonl` (full corpus).
pub fn scanner(root: &Path) -> (usize, usize) {
    let (mut ok, mut n) = (0, 0);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(root.join("tests/fixtures/parity.json")).unwrap()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let known: HashSet<String> = strs(&c["known"]).into_iter().collect();
        let want: Vec<Vec<String>> = c["findings"].as_array().unwrap().iter().map(strs).collect();
        n += 1;
        ok += usize::from(rust_findings(&c["tool"], &known, &strs(&c["scopes"]), true) == want && fingerprint(&c["tool"]) == c["fingerprint"].as_str().unwrap_or(""));
    }
    let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();
    let want: std::collections::HashMap<String, Value> = read("tests/fixtures/parity_corpus.jsonl")
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (v[0].as_str().unwrap().to_string(), v)
        })
        .collect();
    let mut check = |id: String, tool: &Value, known: &HashSet<String>, scopes: &[String]| {
        n += 1;
        if let Some(w) = want.get(&id) {
            let f: Vec<Vec<String>> = w[2].as_array().unwrap().iter().map(strs).collect();
            ok += usize::from(w[1].as_str() == Some(&fingerprint(tool)[..16]) && f == rust_findings(tool, known, scopes, false));
        }
    };
    let attacks: Vec<Attack> = corpus::from_jsonl(&read("corpus/attacks.jsonl"));
    for a in &attacks {
        let mut known: HashSet<String> = a.siblings.iter().chain(a.external.iter()).cloned().collect();
        known.insert(a.tool["name"].as_str().unwrap_or("?").to_string());
        check(a.id.clone(), &a.tool, &known, &a.scopes);
        if let Some(p) = &a.approved {
            check(format!("{}/approved", a.id), p, &known, &a.scopes);
        }
    }
    let benign: Vec<Manifest> = corpus::from_jsonl(&read("corpus/benign.jsonl"));
    for m in &benign {
        let mut names: HashSet<String> = m.tools.iter().map(|t| t["name"].as_str().unwrap_or("?").to_string()).collect();
        names.extend(EXTERNAL.iter().map(|s| s.to_string()));
        for (i, t) in m.tools.iter().enumerate() {
            let sc = m.scopes.get(t["name"].as_str().unwrap_or("?")).cloned().unwrap_or_default();
            check(format!("{}/{i}", m.id), t, &names, &sc);
        }
    }
    (ok, n)
}

/// (matched, total) over `parity_core.json`: canon, PKCE, JWT, negotiation, shims, schema subset.
pub fn core(root: &Path) -> (usize, usize) {
    let fx: Value = serde_json::from_str(&std::fs::read_to_string(root.join("tests/fixtures/parity_core.json")).unwrap()).unwrap();
    let rows = |k: &str| fx[k].as_array().unwrap().iter().map(|r| r.as_array().unwrap().clone()).collect::<Vec<_>>();
    let key = fx["jwt_key"].as_str().unwrap().as_bytes().to_vec();
    let mut res: Vec<bool> = vec![];
    for r in rows("canon") {
        res.push(canon::dumps(&r[0], true, true) == r[1].as_str().unwrap() && canon::dumps(&r[0], false, false) == r[2].as_str().unwrap());
    }
    for r in rows("pkce") {
        res.push(oauth::pkce_challenge(r[0].as_str().unwrap()) == r[1].as_str().unwrap());
    }
    for r in rows("jwt") {
        res.push(oauth::sign_jwt(&r[0], &key) == r[1].as_str().unwrap());
    }
    for r in rows("negotiate") {
        res.push(versions::negotiate(r[0].as_str()) == r[1].as_str().unwrap());
    }
    for r in rows("adapt_tool_def") {
        res.push(versions::adapt_tool_def(&r[0], r[1].as_str().unwrap()) == r[2]);
    }
    for r in rows("adapt_tool_result") {
        let sch = if r[3].is_null() { None } else { Some(&r[3]) };
        res.push(versions::adapt_tool_result(&r[0], r[1].as_str().unwrap(), r[2].as_str().unwrap(), sch) == r[4]);
    }
    for r in rows("validate") {
        res.push(versions::validate(&r[0], &r[1]) == r[2].as_bool().unwrap());
    }
    (res.iter().filter(|x| **x).count(), res.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn scanner_parity_is_total() {
        let (ok, n) = scanner(root());
        assert!(n >= 3206);
        assert_eq!(ok, n);
    }

    #[test]
    fn core_parity_is_total() {
        let (ok, n) = core(root());
        assert!(n >= 600);
        assert_eq!(ok, n);
    }
}
