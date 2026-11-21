//! Parity on the full generated corpus: the Rust v1 scanner must give the same findings and
//! fingerprints as the Python reference on every case (attacks, approved rug-pull snapshots and
//! every benign manifest tool). Fixture: `python3 analysis/gen_parity.py`.

use std::collections::{BTreeMap, HashSet};

use mcpgw::corpus::{self, Attack, Manifest, EXTERNAL};
use mcpgw::scanner::{fingerprint, scan_poisoning, scan_scopes};
use serde_json::Value;

fn expected() -> BTreeMap<String, (String, Vec<Vec<String>>)> {
    include_str!("fixtures/parity_corpus.jsonl")
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            let f = v[2]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect())
                .collect();
            (v[0].as_str().unwrap().to_string(), (v[1].as_str().unwrap().to_string(), f))
        })
        .collect()
}

fn cases() -> Vec<(String, Value, HashSet<String>, Vec<String>)> {
    let attacks: Vec<Attack> = corpus::from_jsonl(include_str!("../corpus/attacks.jsonl"));
    let benign: Vec<Manifest> = corpus::from_jsonl(include_str!("../corpus/benign.jsonl"));
    let mut out = vec![];
    for a in attacks {
        let mut known: HashSet<String> = a.siblings.iter().chain(a.external.iter()).cloned().collect();
        known.insert(a.tool["name"].as_str().unwrap_or("?").to_string());
        out.push((a.id.clone(), a.tool.clone(), known.clone(), a.scopes.clone()));
        if let Some(p) = a.approved {
            out.push((format!("{}/approved", a.id), p, known, a.scopes.clone()));
        }
    }
    for m in benign {
        let mut names: HashSet<String> = m.tools.iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        names.extend(EXTERNAL.iter().map(|s| s.to_string()));
        for (i, t) in m.tools.iter().enumerate() {
            let sc = m.scopes.get(t["name"].as_str().unwrap()).cloned().unwrap_or_default();
            out.push((format!("{}/{i}", m.id), t.clone(), names.clone(), sc));
        }
    }
    out
}

fn rust_row(tool: &Value, known: &HashSet<String>, scopes: &[String]) -> (String, Vec<Vec<String>>) {
    let mut f: Vec<Vec<String>> = scan_poisoning(tool, known)
        .into_iter()
        .chain(scan_scopes(tool, scopes))
        .map(|f| vec![f.rule, f.severity, f.detail])
        .collect();
    f.sort();
    (fingerprint(tool)[..16].to_string(), f)
}

#[test]
fn fixture_covers_every_case() {
    let want = expected();
    let got: Vec<String> = cases().into_iter().map(|c| c.0).collect();
    assert_eq!(want.len(), got.len());
    assert!(want.len() >= 3000, "{}", want.len());
    for id in &got {
        assert!(want.contains_key(id), "{id} missing from fixture");
    }
}

#[test]
fn findings_and_fingerprints_match_python_on_full_corpus() {
    let want = expected();
    let mut bad = vec![];
    for (id, tool, known, scopes) in cases() {
        let got = rust_row(&tool, &known, &scopes);
        if want[&id] != got {
            bad.push(format!("{id}: rust={got:?} python={:?}", want[&id]));
        }
    }
    assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad[..bad.len().min(10)].join("\n"));
}

macro_rules! family_parity {
    ($($name:ident => $fam:expr),* $(,)?) => {$(
        #[test]
        fn $name() {
            let want = expected();
            let attacks: Vec<Attack> = corpus::from_jsonl(include_str!("../corpus/attacks.jsonl"));
            let mut n = 0;
            for a in attacks.iter().filter(|a| a.family == $fam) {
                let mut known: HashSet<String> = a.siblings.iter().chain(a.external.iter()).cloned().collect();
                known.insert(a.tool["name"].as_str().unwrap_or("?").to_string());
                assert_eq!(want[&a.id], rust_row(&a.tool, &known, &a.scopes), "{}", a.id);
                n += 1;
            }
            assert!(n >= 30, "{} has {n}", $fam);
        }
    )*};
}

family_parity! {
    parity_tool_poisoning => "tool_poisoning",
    parity_obfuscated => "obfuscated",
    parity_prompt_injection => "prompt_injection",
    parity_covert_paraphrase => "covert_paraphrase",
    parity_holdout_paraphrase => "holdout_paraphrase",
    parity_shadowing => "shadowing",
    parity_rug_pull => "rug_pull",
    parity_confused_deputy => "confused_deputy",
    parity_exfil => "exfil",
    parity_param_smuggling => "param_smuggling",
    parity_overbroad => "overbroad",
}
