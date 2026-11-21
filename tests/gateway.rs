//! Gateway + OAuth scenarios, mirroring `tests/test_gateway.py` and `tests/test_oauth.py`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use mcpgw::gateway::{AllowEntry, Allowlist, Gateway, GatewayError, Headers, SharedUpstream};
use mcpgw::mocks::{self, MockServer};
use mcpgw::oauth::{
    decode_jwt, pkce_challenge, token_urlsafe, verify_access_token, AuthorizationServer,
    AuthorizeRequest, Clock, TokenRequest, TokenResponse, VerifyParams,
};
use mcpgw::versions;
use serde_json::{json, Value};

const RESOURCE: &str = "https://gw.example/mcp";
const REDIRECT: &str = "http://127.0.0.1:8765/callback";

struct Env {
    t: Rc<Cell<f64>>,
    gw: Gateway,
}

fn clock(t: &Rc<Cell<f64>>) -> Clock {
    let t = t.clone();
    Rc::new(move || t.get())
}

fn allow() -> Vec<AllowEntry> {
    vec![
        AllowEntry::new("weather", "https://weather.example", &[("get_forecast", &["weather:read"])]),
        AllowEntry::new("calc", "https://calc.example", &[("add", &["calc:use"])]).with_output_schema(
            "add",
            json!({"type": "object", "properties": {"sum": {"type": "number"}}, "required": ["sum"]}),
        ),
        AllowEntry::new("notes", "https://notes.example", &[("add_note", &["mcp:read"])]),
        AllowEntry::new("facts", "https://facts.example", &[]),
        AllowEntry::new("translate", "https://translate.example", &[("translate", &["translate:use"])]),
        AllowEntry::new("ops", "https://ops.example", &[("run", &["*", "ops:admin"])]),
    ]
}

fn env() -> Env {
    let t = Rc::new(Cell::new(1_700_000_000.0));
    let mut auth = AuthorizationServer::new(
        "https://auth.example",
        token_urlsafe(32).into_bytes(),
        clock(&t),
    );
    auth.register_client(
        "cli",
        &[REDIRECT],
        &[
            "mcp:read",
            "weather:read",
            "calc:use",
            "translate:use",
            "ops:run",
        ],
    )
    .unwrap();
    let gw = Gateway::new(RESOURCE, auth, Allowlist::new(allow()), clock(&t));
    Env { t, gw }
}

fn get_token(auth: &mut AuthorizationServer, scope: &str, resource: &str) -> TokenResponse {
    let verifier = token_urlsafe(40);
    let code = auth
        .authorize(AuthorizeRequest {
            client_id: "cli",
            redirect_uri: REDIRECT,
            scope,
            code_challenge: Some(&pkce_challenge(&verifier)),
            code_challenge_method: Some("S256"),
            resource: Some(resource),
        })
        .unwrap();
    auth.token(TokenRequest {
        grant_type: "authorization_code",
        client_id: "cli",
        code: Some(&code),
        code_verifier: Some(&verifier),
        redirect_uri: Some(REDIRECT),
        resource: Some(resource),
        ..Default::default()
    })
    .unwrap()
}

fn token(e: &mut Env) -> String {
    get_token(
        &mut e.gw.auth,
        "mcp:read weather:read calc:use translate:use",
        RESOURCE,
    )
    .access_token
}

fn hdr(pairs: &[(&str, &str)]) -> Headers {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

struct Client {
    token: String,
    sid: String,
    version: String,
}

impl Client {
    fn new(gw: &mut Gateway, token: &str, version: &str) -> Client {
        let (st, h, body) = gw.handle_http(
            &hdr(&[("Authorization", &format!("Bearer {token}"))]),
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": version}}),
        );
        assert_eq!(st, 200);
        Client {
            token: token.into(),
            sid: h["Mcp-Session-Id"].clone(),
            version: body["result"]["protocolVersion"].as_str().unwrap().into(),
        }
    }

    fn rpc(
        &self,
        gw: &mut Gateway,
        method: &str,
        params: Value,
        extra: &[(&str, &str)],
    ) -> (u16, Headers, Value) {
        let mut h = hdr(&[
            ("Authorization", &format!("Bearer {}", self.token)),
            ("Mcp-Session-Id", &self.sid),
            ("MCP-Protocol-Version", &self.version),
        ]);
        for (k, v) in extra {
            h.insert(k.to_string(), v.to_string());
        }
        gw.handle_http(
            &h,
            &json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params}),
        )
    }
}

fn up(m: &Rc<RefCell<MockServer>>) -> SharedUpstream {
    m.clone()
}

// ---------------- gateway ----------------

#[test]
fn allowlist_blocks_unknown_and_url_swap() {
    let mut e = env();
    let s = mocks::weather().shared();
    s.borrow_mut().url = "https://weather-evil.example".into();
    match e.gw.connect("weather", up(&s)) {
        Err(GatewayError::Permission(m)) => assert!(m.contains("does not match pinned")),
        other => panic!("{other:?}"),
    }
    match e.gw.connect("random", up(&mocks::weather().shared())) {
        Err(GatewayError::Permission(m)) => assert!(m.contains("not on the allowlist")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn version_negotiation() {
    let mut e = env();
    let t = token(&mut e);
    assert_eq!(
        Client::new(&mut e.gw, &t, "2025-03-26").version,
        "2025-03-26"
    );
    assert_eq!(
        Client::new(&mut e.gw, &t, "1999-01-01").version,
        versions::LATEST
    );
}

#[test]
fn protocol_header_mismatch_rejected() {
    let mut e = env();
    let t = token(&mut e);
    let c = Client::new(&mut e.gw, &t, "2025-06-18");
    let (st, _, body) = c.rpc(
        &mut e.gw,
        "ping",
        json!({}),
        &[("MCP-Protocol-Version", "2025-03-26")],
    );
    assert!(
        st == 400
            && body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("negotiated")
    );
    assert_eq!(c.rpc(&mut e.gw, "ping", json!({}), &[]).0, 200);
}

#[test]
fn batching_only_in_2025_03_26() {
    let mut e = env();
    let t = token(&mut e);
    let batch = json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 2, "method": "ping"}]);
    let old = Client::new(&mut e.gw, &t, "2025-03-26");
    let auth = format!("Bearer {t}");
    let (st, _, body) = e.gw.handle_http(
        &hdr(&[("Authorization", &auth), ("Mcp-Session-Id", &old.sid)]),
        &batch,
    );
    assert_eq!(st, 200);
    assert_eq!(
        body.as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let new = Client::new(&mut e.gw, &t, "2025-06-18");
    let (st, _, body) = e.gw.handle_http(
        &hdr(&[("Authorization", &auth), ("Mcp-Session-Id", &new.sid)]),
        &batch,
    );
    assert!(
        st == 400
            && body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("batching")
    );
}

#[test]
fn upgrade_shim_lifts_legacy_text_to_structured() {
    let mut e = env();
    let t = token(&mut e);
    let s = mocks::legacy_calc().shared();
    e.gw.connect("calc", up(&s)).unwrap();
    assert_eq!(e.gw.servers["calc"].version, "2024-11-05");
    e.gw.approve("calc");
    let c = Client::new(&mut e.gw, &t, "2025-06-18");
    let (_, _, body) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "calc__add", "arguments": {"a": 2, "b": 3}}),
        &[],
    );
    assert_eq!(body["result"]["structuredContent"], json!({"sum": 5}));
    // upstream on 2024-11-05 must not receive the 2025-06-18 header
    let last = s.borrow().received.last().unwrap().1.clone();
    assert!(!last.contains_key("MCP-Protocol-Version"));
}

#[test]
fn downgrade_shim_strips_new_fields() {
    let mut e = env();
    let t = token(&mut e);
    e.gw.connect("weather", up(&mocks::weather().shared()))
        .unwrap();
    e.gw.approve("weather");
    let c = Client::new(&mut e.gw, &t, "2024-11-05");
    let (_, _, body) = c.rpc(&mut e.gw, "tools/list", json!({}), &[]);
    let tool = &body["result"]["tools"][0];
    assert_eq!(tool["name"], "weather__get_forecast");
    for k in ["annotations", "outputSchema", "title"] {
        assert!(tool.get(k).is_none(), "{k} not stripped");
    }
    let (_, _, body) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "weather__get_forecast", "arguments": {"city": "x"}}),
        &[],
    );
    assert!(body["result"].get("structuredContent").is_none());
    assert_eq!(body["result"]["content"][0]["type"], "text");
}

#[test]
fn poisoned_server_rejected_and_never_called() {
    let mut e = env();
    let t = token(&mut e);
    let s = mocks::poisoned_notes().shared();
    e.gw.connect("notes", up(&s)).unwrap();
    let rules: Vec<String> = e.gw.approve("notes").into_iter().map(|f| f.rule).collect();
    for r in ["TP001", "TP002", "TP003", "TP008"] {
        assert!(rules.contains(&r.to_string()), "{r} missing from {rules:?}");
    }
    let c = Client::new(&mut e.gw, &t, "2025-06-18");
    let (_, _, body) = c.rpc(&mut e.gw, "tools/list", json!({}), &[]);
    assert_eq!(body["result"]["tools"], json!([]));
    let (_, _, body) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "notes__add_note", "arguments": {"text": "hi"}}),
        &[],
    );
    assert!(body.get("error").is_some() && s.borrow().calls().is_empty());
}

#[test]
fn shadowing_detected() {
    let mut e = env();
    e.gw.connect("facts", up(&mocks::shadowing().shared()))
        .unwrap();
    let findings = e.gw.approve("facts");
    assert!(findings
        .iter()
        .any(|f| f.rule == "TP005" && f.tool == "daily_tip"));
    assert_eq!(
        e.gw.servers["facts"].status,
        mcpgw::gateway::Status::Rejected
    );
}

#[test]
fn rug_pull_quarantines_tool() {
    let mut e = env();
    let t = token(&mut e);
    let s = mocks::rug_pull().shared();
    e.gw.connect("translate", up(&s)).unwrap();
    assert!(e.gw.approve("translate").is_empty());
    let c = Client::new(&mut e.gw, &t, "2025-06-18");
    let (_, _, body) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "translate__translate", "arguments": {"text": "hola"}}),
        &[],
    );
    assert_eq!(body["result"]["content"][0]["text"], "hola");
    s.borrow_mut().flip();
    let (_, _, body) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "translate__translate", "arguments": {"text": "secret"}}),
        &[],
    );
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("quarantined"));
    assert_eq!(s.borrow().calls().len(), 1); // second call never reached upstream
    assert!(e
        .gw
        .audit
        .iter()
        .any(|a| a["event"] == "quarantine" && a["rule"] == "RP001"));
}

#[test]
fn overbroad_scopes_flagged() {
    let mut e = env();
    e.gw.connect("ops", up(&mocks::overbroad().shared()))
        .unwrap();
    let rules: Vec<String> = e.gw.approve("ops").into_iter().map(|f| f.rule).collect();
    for r in ["SC001", "SC003", "SC004"] {
        assert!(rules.contains(&r.to_string()));
    }
}

#[test]
fn no_token_passthrough() {
    let mut e = env();
    let t = token(&mut e);
    let s = mocks::weather().shared();
    e.gw.connect("weather", up(&s)).unwrap();
    e.gw.approve("weather");
    let c = Client::new(&mut e.gw, &t, "2025-06-18");
    let (_, _, body) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "weather__get_forecast", "arguments": {"city": "x"}}),
        &[],
    );
    assert_eq!(body["result"]["structuredContent"], json!({"temp_c": 21.5}));
    assert!(s
        .borrow()
        .received
        .iter()
        .all(|(_, h)| !format!("{h:?}").contains(&t)));
}

#[test]
fn insufficient_scope_403_and_upstream_not_called() {
    let mut e = env();
    let t = get_token(&mut e.gw.auth, "mcp:read", RESOURCE).access_token;
    let s = mocks::weather().shared();
    e.gw.connect("weather", up(&s)).unwrap();
    e.gw.approve("weather");
    let c = Client::new(&mut e.gw, &t, "2025-06-18");
    let (st, h, _) = c.rpc(
        &mut e.gw,
        "tools/call",
        json!({"name": "weather__get_forecast", "arguments": {"city": "x"}}),
        &[],
    );
    assert_eq!(st, 403);
    assert!(
        h["WWW-Authenticate"].contains("insufficient_scope")
            && h["WWW-Authenticate"].contains("weather:read")
    );
    assert!(s.borrow().calls().is_empty());
}

#[test]
fn missing_bearer_gets_rfc9728_challenge() {
    let mut e = env();
    let (st, h, _) = e.gw.handle_http(
        &Headers::new(),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    );
    assert_eq!(st, 401);
    assert!(h["WWW-Authenticate"].contains("/.well-known/oauth-protected-resource"));
    let prm = e.gw.well_known();
    assert_eq!(prm["resource"], RESOURCE);
    assert!(prm["scopes_supported"]
        .as_array()
        .unwrap()
        .contains(&json!("weather:read")));
}

// ---------------- oauth ----------------

#[test]
fn metadata_is_s256_only() {
    let e = env();
    assert_eq!(
        e.gw.auth.metadata()["code_challenge_methods_supported"],
        json!(["S256"])
    );
}

#[test]
fn plain_or_missing_pkce_rejected() {
    let mut e = env();
    let v = token_urlsafe(40);
    for (ch, method) in [(Some(v.as_str()), Some("plain")), (None, Some("S256"))] {
        let err =
            e.gw.auth
                .authorize(AuthorizeRequest {
                    client_id: "cli",
                    redirect_uri: REDIRECT,
                    scope: "mcp:read",
                    code_challenge: ch,
                    code_challenge_method: method,
                    resource: Some(RESOURCE),
                })
                .unwrap_err();
        assert_eq!(err.error, "invalid_request");
    }
}

#[test]
fn wrong_verifier_and_redirect_mismatch() {
    let mut e = env();
    let v = token_urlsafe(40);
    let ch = pkce_challenge(&v);
    let mk = |a: &mut AuthorizationServer| {
        a.authorize(AuthorizeRequest {
            client_id: "cli",
            redirect_uri: REDIRECT,
            scope: "mcp:read",
            code_challenge: Some(&ch),
            code_challenge_method: Some("S256"),
            resource: Some(RESOURCE),
        })
        .unwrap()
    };
    let code = mk(&mut e.gw.auth);
    let err =
        e.gw.auth
            .token(TokenRequest {
                grant_type: "authorization_code",
                client_id: "cli",
                code: Some(&code),
                code_verifier: Some("wrong"),
                redirect_uri: Some(REDIRECT),
                resource: Some(RESOURCE),
                ..Default::default()
            })
            .unwrap_err();
    assert_eq!(err.description, "PKCE verification failed");
    let code = mk(&mut e.gw.auth);
    let err =
        e.gw.auth
            .token(TokenRequest {
                grant_type: "authorization_code",
                client_id: "cli",
                code: Some(&code),
                code_verifier: Some(&v),
                redirect_uri: Some("http://127.0.0.1:9999/cb"),
                resource: Some(RESOURCE),
                ..Default::default()
            })
            .unwrap_err();
    assert_eq!(err.description, "client or redirect mismatch");
}

#[test]
fn code_replay_revokes_first_token() {
    let mut e = env();
    let v = token_urlsafe(40);
    let code =
        e.gw.auth
            .authorize(AuthorizeRequest {
                client_id: "cli",
                redirect_uri: REDIRECT,
                scope: "mcp:read",
                code_challenge: Some(&pkce_challenge(&v)),
                code_challenge_method: Some("S256"),
                resource: Some(RESOURCE),
            })
            .unwrap();
    let req = || TokenRequest {
        grant_type: "authorization_code",
        client_id: "cli",
        code: Some(&code),
        code_verifier: Some(&v),
        redirect_uri: Some(REDIRECT),
        resource: Some(RESOURCE),
        ..Default::default()
    };
    let first = e.gw.auth.token(req()).unwrap();
    assert_eq!(
        e.gw.auth.token(req()).unwrap_err().description,
        "code already used"
    );
    let (st, _, body) = e.gw.handle_http(
        &hdr(&[("Authorization", &format!("Bearer {}", first.access_token))]),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    );
    assert_eq!(
        (st, body["error_description"].as_str().unwrap()),
        (401, "revoked")
    );
}

#[test]
fn token_for_other_resource_rejected() {
    let mut e = env();
    let t = get_token(&mut e.gw.auth, "mcp:read", "https://other.example/mcp").access_token;
    let (st, _, body) = e.gw.handle_http(
        &hdr(&[("Authorization", &format!("Bearer {t}"))]),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    );
    assert_eq!(st, 401);
    assert_eq!(
        body["error_description"],
        "token audience is not this resource"
    );
}

#[test]
fn expired_and_tampered_tokens() {
    let mut e = env();
    let t = token(&mut e);
    let key = e.gw.auth.key.clone();
    let p = |now: f64| VerifyParams {
        key: &key,
        issuer: "https://auth.example",
        audience: RESOURCE,
        required_scopes: &[],
        now,
        revocation: None,
    };
    let now = e.t.get();
    assert!(verify_access_token(&t, p(now)).is_ok());
    assert_eq!(
        verify_access_token(&t, p(now + 301.0))
            .unwrap_err()
            .description,
        "expired"
    );
    let mut parts: Vec<String> = t.split('.').map(String::from).collect();
    let mut claims = decode_jwt(&t, &key).unwrap();
    claims["scope"] = json!("ops:run");
    parts[1] = mcpgw::oauth::b64url(mcpgw::canon::dumps(&claims, true, true).as_bytes());
    assert_eq!(
        verify_access_token(&parts.join("."), p(now))
            .unwrap_err()
            .description,
        "bad signature"
    );
}

#[test]
fn refresh_rotation_and_reuse_kills_family() {
    let mut e = env();
    let first = get_token(&mut e.gw.auth, "mcp:read", RESOURCE);
    let refresh = |a: &mut AuthorizationServer, rt: &str| {
        a.token(TokenRequest {
            grant_type: "refresh_token",
            client_id: "cli",
            refresh_token: Some(rt),
            ..Default::default()
        })
    };
    let second = refresh(&mut e.gw.auth, &first.refresh_token).unwrap();
    assert_ne!(second.refresh_token, first.refresh_token);
    let err = refresh(&mut e.gw.auth, &first.refresh_token).unwrap_err();
    assert!(err.description.contains("reuse detected"));
    assert_eq!(
        refresh(&mut e.gw.auth, &second.refresh_token)
            .unwrap_err()
            .description,
        "token family revoked"
    );
    let claims = decode_jwt(&second.access_token, &e.gw.auth.key).unwrap();
    assert!(e.gw.auth.is_revoked(&claims));
}
