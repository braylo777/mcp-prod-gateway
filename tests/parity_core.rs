//! Core parity with the Python reference beyond the scanner: canonical JSON, PKCE, HS256 JWT,
//! version negotiation, both version shims and the schema subset. Fixture:
//! `python3 analysis/gen_parity_core.py`.

use mcpgw::{canon, oauth, versions};
use serde_json::Value;

fn fx() -> Value {
    serde_json::from_str(include_str!("fixtures/parity_core.json")).unwrap()
}

fn rows(k: &str) -> Vec<Vec<Value>> {
    fx()[k].as_array().unwrap().iter().map(|r| r.as_array().unwrap().clone()).collect()
}

#[test]
fn canon_sorted_compact_matches_json_dumps() {
    let bad: Vec<String> = rows("canon")
        .iter()
        .filter(|r| canon::dumps(&r[0], true, true) != r[1].as_str().unwrap())
        .map(|r| format!("{} != {}", canon::dumps(&r[0], true, true), r[1]))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn canon_default_separators_match_json_dumps() {
    let bad: Vec<String> = rows("canon")
        .iter()
        .filter(|r| canon::dumps(&r[0], false, false) != r[2].as_str().unwrap())
        .map(|r| format!("{} != {}", canon::dumps(&r[0], false, false), r[2]))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn pkce_matches() {
    for r in rows("pkce") {
        assert_eq!(oauth::pkce_challenge(r[0].as_str().unwrap()), r[1].as_str().unwrap());
    }
}

#[test]
fn jwt_signatures_match() {
    let key = fx()["jwt_key"].as_str().unwrap().as_bytes().to_vec();
    for r in rows("jwt") {
        let tok = oauth::sign_jwt(&r[0], &key);
        assert_eq!(tok, r[1].as_str().unwrap());
        assert_eq!(oauth::decode_jwt(&tok, &key).unwrap(), r[0]);
    }
}

#[test]
fn negotiate_matches() {
    for r in rows("negotiate") {
        assert_eq!(versions::negotiate(r[0].as_str()), r[1].as_str().unwrap(), "{:?}", r[0]);
    }
}

#[test]
fn adapt_tool_def_matches() {
    let rs = rows("adapt_tool_def");
    assert!(rs.len() >= 160);
    for r in rs {
        assert_eq!(versions::adapt_tool_def(&r[0], r[1].as_str().unwrap()), r[2]);
    }
}

#[test]
fn adapt_tool_result_matches() {
    let rs = rows("adapt_tool_result");
    assert!(rs.len() >= 280);
    for r in rs {
        let sch = if r[3].is_null() { None } else { Some(&r[3]) };
        let got = versions::adapt_tool_result(&r[0], r[1].as_str().unwrap(), r[2].as_str().unwrap(), sch);
        assert_eq!(got, r[4], "{} {} {}", r[0], r[1], r[2]);
    }
}

#[test]
fn schema_subset_matches_jsonschema() {
    for r in rows("validate") {
        assert_eq!(versions::validate(&r[0], &r[1]), r[2].as_bool().unwrap(), "{} vs {}", r[0], r[1]);
    }
}
