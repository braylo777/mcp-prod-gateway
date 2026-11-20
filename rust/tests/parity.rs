//! Parity: the Rust scanner must give the same findings and fingerprints as the Python scanner
//! on all 48 cases (40-tool labelled corpus + every mock server, incl. the flipped rug pull).
//! Fixture written by the Python code; see README "Parity".

use std::collections::{BTreeMap, HashSet};

use mcpgw::scanner::{fingerprint, scan_poisoning, scan_scopes, HIGH, MEDIUM};
use serde_json::Value;

fn fixture() -> Vec<Value> {
    let raw = include_str!("fixtures/parity.json");
    let v: Value = serde_json::from_str(raw).unwrap();
    v["cases"].as_array().unwrap().clone()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn scanner_and_fingerprint_match_python() {
    let cases = fixture();
    assert_eq!(cases.len(), 48);
    let mut mismatches = vec![];
    for c in &cases {
        let tool = &c["tool"];
        let known: HashSet<String> = strs(&c["known"]).into_iter().collect();
        let mut got: Vec<Vec<String>> = scan_poisoning(tool, &known)
            .into_iter()
            .chain(scan_scopes(tool, &strs(&c["scopes"])))
            .map(|f| vec![f.rule, f.severity, f.tool, f.detail])
            .collect();
        got.sort();
        let want: Vec<Vec<String>> = c["findings"].as_array().unwrap().iter().map(strs).collect();
        if got != want {
            mismatches.push(format!("{}: rust={got:?} python={want:?}", tool["name"]));
        }
        assert_eq!(
            fingerprint(tool),
            c["fingerprint"].as_str().unwrap(),
            "fingerprint {}",
            tool["name"]
        );
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn corpus_eval_gate_same_as_python() {
    // Python: recall 19/20 (0.95), FPR 0/20, the paraphrase case is the one miss.
    let (mut tp, mut fp, mut fneg, mut tn) = (0, 0, 0, 0);
    let mut misses = vec![];
    for c in fixture().iter().filter(|c| !c["label"].is_null()) {
        let tool = &c["tool"];
        let known: HashSet<String> = strs(&c["known"]).into_iter().collect();
        let flagged = scan_poisoning(tool, &known)
            .into_iter()
            .chain(scan_scopes(tool, &strs(&c["scopes"])))
            .any(|f| f.severity == HIGH || f.severity == MEDIUM);
        match (c["label"].as_i64().unwrap() == 1, flagged) {
            (true, true) => tp += 1,
            (true, false) => {
                fneg += 1;
                misses.push(tool["name"].as_str().unwrap().to_string())
            }
            (false, true) => fp += 1,
            (false, false) => tn += 1,
        }
    }
    assert_eq!((tp, fneg, fp, tn), (19, 1, 0, 20));
    assert_eq!(misses, vec!["polite"]);
    let _ = BTreeMap::<String, String>::new();
}
