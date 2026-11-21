//! Corpus gates: committed JSONL equals the generator, sizes, per-family recall floors and the
//! benign false-positive ceiling. Floors are the measured values; a drop fails CI.

use std::collections::HashSet;

use mcpgw::corpus::{self, Attack, Manifest};
use mcpgw::eval;

fn committed() -> (Vec<Attack>, Vec<Manifest>) {
    (corpus::from_jsonl(include_str!("../corpus/attacks.jsonl")), corpus::from_jsonl(include_str!("../corpus/benign.jsonl")))
}

#[test]
fn committed_attacks_match_generator() {
    assert!(corpus::to_jsonl(&corpus::attacks()) == include_str!("../corpus/attacks.jsonl"), "run `cargo run --bin gen-corpus`");
}

#[test]
fn committed_benign_match_generator() {
    assert!(corpus::to_jsonl(&corpus::benign()) == include_str!("../corpus/benign.jsonl"), "run `cargo run --bin gen-corpus`");
}

#[test]
fn generator_is_deterministic() {
    assert_eq!(corpus::attacks(), corpus::attacks());
    assert_eq!(corpus::benign()[..50], corpus::benign()[..50]);
}

#[test]
fn sizes() {
    let (a, b) = committed();
    assert!(a.len() >= 500, "{}", a.len());
    assert_eq!(b.len(), 1000);
    assert!(b.iter().map(|m| m.tools.len()).sum::<usize>() >= 2000);
}

#[test]
fn ids_unique() {
    let (a, b) = committed();
    assert_eq!(a.iter().map(|x| &x.id).collect::<HashSet<_>>().len(), a.len());
    assert_eq!(b.iter().map(|x| &x.id).collect::<HashSet<_>>().len(), b.len());
}

#[test]
fn every_family_and_mutation_present() {
    let (a, _) = committed();
    let fams: HashSet<&str> = a.iter().map(|x| x.family.as_str()).collect();
    assert_eq!(fams.len(), 11);
    for m in corpus::OBF_MUTS {
        assert!(a.iter().any(|x| x.mutation.starts_with(m)), "{m}");
    }
    for c in corpus::CARRIERS {
        assert!(a.iter().any(|x| x.mutation.ends_with(&format!("@{c}"))), "{c}");
    }
}

#[test]
fn rug_pulls_have_snapshot() {
    let (a, _) = committed();
    for x in a.iter().filter(|x| x.family == "rug_pull") {
        assert!(x.approved.is_some() && x.approved.as_ref() != Some(&x.tool), "{}", x.id);
    }
}

#[test]
fn no_real_looking_secrets_or_domains() {
    // GitHub push protection: no token-shaped strings; sinks use reserved names only.
    let all = format!("{}{}", include_str!("../corpus/attacks.jsonl"), include_str!("../corpus/benign.jsonl"));
    for bad in ["ghp_", "github_pat_", "AKIA", "sk-", "xoxb-", "-----BEGIN", "AIza"] {
        assert!(!all.contains(bad), "{bad}");
    }
    let re = regex::Regex::new(r"https?://([a-z0-9.-]+)").unwrap();
    for c in re.captures_iter(&all) {
        let host = &c[1];
        assert!(
            host.ends_with(".example") || host.ends_with(".invalid") || host.ends_with("example.com") || host.starts_with("192.0.2.") || host.starts_with("198.51.100.") || host.starts_with("203.0.113."),
            "{host}"
        );
    }
}

fn report() -> eval::Report {
    let (a, b) = committed();
    eval::run(&a, &b)
}

#[test]
fn overall_recall_floor() {
    let r = report();
    assert!(r.caught >= 650, "{}/{}", r.caught, r.attacks);
}

#[test]
fn benign_fp_ceiling() {
    let r = report();
    assert_eq!(r.fp_manifests, 0, "{:?}", r.fp_examples);
}

#[test]
fn misses_are_only_the_holdout_family() {
    let r = report();
    assert!(r.misses.iter().all(|m| m.contains("holdout_paraphrase")), "{:?}", r.misses);
}

macro_rules! floor {
    ($($n:ident: $fam:expr => $min:expr;)*) => {$(
        #[test]
        fn $n() {
            let r = report();
            let (c, t) = r.per_family[$fam];
            assert!(c >= $min, "{}: {c}/{t}", $fam);
        }
    )*};
}

floor! {
    recall_tool_poisoning: "tool_poisoning" => 120;
    recall_obfuscated: "obfuscated" => 110;
    recall_prompt_injection: "prompt_injection" => 70;
    recall_covert_paraphrase: "covert_paraphrase" => 50;
    recall_shadowing: "shadowing" => 70;
    recall_rug_pull: "rug_pull" => 70;
    recall_confused_deputy: "confused_deputy" => 60;
    recall_exfil: "exfil" => 40;
    recall_param_smuggling: "param_smuggling" => 30;
    recall_overbroad: "overbroad" => 30;
}

#[test]
fn holdout_is_reported_honestly() {
    // Held-out paraphrases use vocabulary outside every rule lexicon: 0/40 is the honest result.
    let r = report();
    assert_eq!(r.per_family["holdout_paraphrase"], (0, 40));
}

#[test]
fn v1_alone_is_weaker_than_policy() {
    // The deep layer must add real recall over the parity-locked v1 rules.
    use mcpgw::scanner::{scan_poisoning, scan_scopes};
    let (a, _) = committed();
    let v1 = a
        .iter()
        .filter(|x| x.approved.is_none())
        .filter(|x| {
            let mut k: HashSet<String> = x.siblings.iter().chain(x.external.iter()).cloned().collect();
            k.insert(x.tool["name"].as_str().unwrap_or("?").into());
            let f: Vec<_> = scan_poisoning(&x.tool, &k).into_iter().chain(scan_scopes(&x.tool, &x.scopes)).collect();
            mcpgw::policy::flagged(&f)
        })
        .count();
    let full = a.iter().filter(|x| x.approved.is_none()).filter(|x| eval::caught(x)).count();
    assert!(full > v1 + 50, "v1 {v1} vs policy {full}");
}
