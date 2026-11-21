//! Property-based fuzzing (proptest) of the parsers and scanners. Run more cases with
//! `PROPTEST_CASES=20000 cargo test --release --test fuzz`.

use std::collections::{BTreeMap, HashSet};

use mcpgw::corpus::{mutate, Rng, OBF_MUTS, PLAIN_MUTS};
use mcpgw::http::{parse_request, parse_response, write_response, ParseError};
use mcpgw::scanner::{diff_against_approved, fingerprint, scan_poisoning, scan_scopes};
use mcpgw::{canon, oauth, policy};
use proptest::prelude::*;
use serde_json::{json, Map, Value};

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<f64>().prop_filter("finite", |f| f.is_finite()).prop_map(|f| json!(f)),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((any::<String>(), inner), 0..6).prop_map(|kv| Value::Object(kv.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

fn arb_tool() -> impl Strategy<Value = Value> {
    (any::<String>(), any::<String>(), prop::collection::vec((any::<String>(), arb_json()), 0..4), arb_json()).prop_map(|(name, desc, props, extra)| {
        let p: Map<String, Value> = props.into_iter().collect();
        json!({"name": name, "description": desc, "inputSchema": {"type": "object", "properties": p}, "annotations": extra})
    })
}

fn token() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_".to_vec()), 1..16).prop_map(|v| String::from_utf8(v).unwrap())
}

fn valid_request() -> impl Strategy<Value = (String, String, Vec<(String, String)>, Vec<u8>)> {
    (
        prop::sample::select(vec!["GET", "POST", "PUT", "DELETE"]),
        token().prop_map(|t| format!("/{t}")),
        prop::collection::vec((token(), token()), 0..6),
        prop::collection::vec(any::<u8>(), 0..256),
    )
        .prop_map(|(m, p, h, b)| (m.to_string(), p, h.into_iter().filter(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding")).collect(), b))
}

fn render(m: &str, p: &str, h: &[(String, String)], b: &[u8]) -> Vec<u8> {
    let mut s = format!("{m} {p} HTTP/1.1\r\n");
    for (k, v) in h {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    s.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
    let mut out = s.into_bytes();
    out.extend_from_slice(b);
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn parse_request_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_request(&bytes);
    }

    #[test]
    fn parse_request_garbage_after_valid_head(junk in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut b = b"POST / HTTP/1.1\r\nX: ".to_vec();
        b.extend(junk);
        let _ = parse_request(&b);
    }

    #[test]
    fn valid_requests_roundtrip((m, p, h, b) in valid_request()) {
        let raw = render(&m, &p, &h, &b);
        let (r, n) = parse_request(&raw).unwrap();
        prop_assert_eq!(n, raw.len());
        prop_assert_eq!(r.method, m);
        prop_assert_eq!(r.path, p);
        prop_assert_eq!(r.body, b);
        for (k, _) in &h {
            prop_assert!(r.headers.keys().any(|x| x.eq_ignore_ascii_case(k)));
        }
    }

    #[test]
    fn every_prefix_is_incomplete_or_ok((m, p, h, b) in valid_request(), cut in 0usize..1000) {
        let raw = render(&m, &p, &h, &b);
        let cut = cut % (raw.len() + 1);
        match parse_request(&raw[..cut]) {
            Ok(_) | Err(ParseError::Incomplete) => {}
            Err(e) => prop_assert!(false, "prefix {cut}/{} gave {e:?}", raw.len()),
        }
    }

    #[test]
    fn response_roundtrip(status in 100u16..600, body in arb_json()) {
        let bytes = write_response(status, &Default::default(), &body);
        let (st, _, b) = parse_response(&bytes).unwrap();
        prop_assert_eq!(st, status);
        let back: Value = serde_json::from_slice(&b).unwrap();
        prop_assert_eq!(back, body);
    }

    #[test]
    fn parse_response_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_response(&bytes);
    }

    #[test]
    fn scanners_never_panic(tool in arb_tool(), scopes in prop::collection::vec(any::<String>(), 0..4)) {
        let known: HashSet<String> = ["send_email".to_string()].into();
        let _ = scan_poisoning(&tool, &known);
        let _ = scan_scopes(&tool, &scopes);
        let _ = policy::scan_tool(&tool, &HashSet::new(), &known, &scopes);
    }

    #[test]
    fn scanners_never_panic_on_any_json(v in arb_json()) {
        let _ = policy::scan_tool(&v, &HashSet::new(), &HashSet::new(), &[]);
        let _ = fingerprint(&v);
    }

    #[test]
    fn normalize_strips_invisible(s in any::<String>()) {
        let n = policy::normalize(&s);
        prop_assert!(!n.chars().any(|c| matches!(c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF | 0xE0000..=0xE007F | 0x00AD)));
        prop_assert!(!n.starts_with(' ') && !n.ends_with(' '));
    }

    #[test]
    fn fingerprint_deterministic_and_sensitive(tool in arb_tool(), extra in any::<String>()) {
        prop_assert_eq!(fingerprint(&tool), fingerprint(&tool.clone()));
        let mut t2 = tool.clone();
        let d = t2["description"].as_str().unwrap().to_string();
        t2["description"] = Value::String(format!("{d}{extra}x"));
        prop_assert_ne!(fingerprint(&tool), fingerprint(&t2));
    }

    #[test]
    fn rug_pull_always_detected(tool in arb_tool(), extra in any::<String>()) {
        let name = tool["name"].as_str().unwrap().to_string();
        let approved = BTreeMap::from([(name.clone(), fingerprint(&tool))]);
        prop_assert!(diff_against_approved(std::slice::from_ref(&tool), &approved).is_empty());
        let mut t2 = tool.clone();
        t2["description"] = Value::String(format!("{extra}!"));
        if t2 != tool {
            let f = diff_against_approved(&[t2], &approved);
            prop_assert!(f.iter().any(|x| x.rule == "RP001"));
        }
    }

    #[test]
    fn canon_is_valid_json(v in arb_json()) {
        let s = canon::dumps(&v, true, true);
        let back: Value = serde_json::from_str(&s).unwrap();
        prop_assert!(s.is_ascii());
        prop_assert_eq!(canon::dumps(&back, true, true), s);
    }

    #[test]
    fn jwt_roundtrip_and_tamper(claims in prop::collection::btree_map(token(), any::<String>(), 0..6), key in prop::collection::vec(any::<u8>(), 1..64)) {
        let c: Value = serde_json::to_value(&claims).unwrap();
        let tok = oauth::sign_jwt(&c, &key);
        prop_assert_eq!(oauth::decode_jwt(&tok, &key).unwrap(), c);
        let mut parts: Vec<String> = tok.split('.').map(String::from).collect();
        parts[1] = oauth::b64url(b"{\"admin\":true}");
        prop_assert!(oauth::decode_jwt(&parts.join("."), &key).is_err());
    }

    #[test]
    fn decode_jwt_never_panics(s in any::<String>()) {
        let _ = oauth::decode_jwt(&s, b"k");
    }

    #[test]
    fn osa_symmetric_and_bounded(a in any::<String>(), b in any::<String>()) {
        let (x, y) = (policy::osa_distance(&a, &b), policy::osa_distance(&b, &a));
        prop_assert_eq!(x, y);
        prop_assert!(x <= a.chars().count().max(b.chars().count()));
    }

    #[test]
    fn mutations_never_panic(s in any::<String>(), seed in any::<u64>()) {
        let mut r = Rng::new(seed);
        for m in PLAIN_MUTS.iter().chain(OBF_MUTS) {
            let _ = mutate(&s, m, &mut r);
        }
    }
}
