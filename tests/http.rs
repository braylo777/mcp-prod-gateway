//! HTTP binding: strict parser cases plus the full flow over a real localhost socket
//! (mirrors `reference/tests/test_gateway.py::test_over_real_http`).

use std::sync::mpsc;

use mcpgw::gateway::{AllowEntry, Allowlist, Gateway};
use mcpgw::http::{self, parse_request, parse_response, write_response, ParseError, MAX_BODY, MAX_HEAD};
use mcpgw::mocks;
use mcpgw::oauth::{pkce_challenge, token_urlsafe, AuthorizationServer, AuthorizeRequest, TokenRequest};
use serde_json::{json, Value};

fn req(s: &str) -> Result<(http::Request, usize), ParseError> {
    parse_request(s.as_bytes())
}

#[test]
fn parses_post_with_body() {
    let (r, n) = req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}").unwrap();
    assert_eq!((r.method.as_str(), r.path.as_str(), r.body.as_slice(), n), ("POST", "/", &b"{}"[..], 49));
}
#[test]
fn parses_get_without_body() {
    let (r, _) = req("GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(r.path, http::WELL_KNOWN);
    assert!(r.body.is_empty());
}
#[test]
fn keeps_header_case_and_trims() {
    let (r, _) = req("GET / HTTP/1.1\r\nMcp-Session-Id:   abc \r\n\r\n").unwrap();
    assert_eq!(r.headers["Mcp-Session-Id"], "abc");
}
#[test]
fn duplicate_header_keeps_first() {
    let (r, _) = req("GET / HTTP/1.1\r\nX-A: 1\r\nx-a: 2\r\n\r\n").unwrap();
    assert_eq!(r.headers.len(), 1);
    assert_eq!(r.headers["X-A"], "1");
}
#[test]
fn http10_ok() {
    assert!(req("GET / HTTP/1.0\r\n\r\n").is_ok());
}
#[test]
fn incomplete_head() {
    assert_eq!(req("POST / HTTP/1.1\r\nHost: x\r\n").unwrap_err(), ParseError::Incomplete);
}
#[test]
fn incomplete_body() {
    assert_eq!(req("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}").unwrap_err(), ParseError::Incomplete);
}
#[test]
fn head_too_large() {
    let s = format!("GET / HTTP/1.1\r\nX: {}", "a".repeat(MAX_HEAD + 10));
    assert_eq!(req(&s).unwrap_err(), ParseError::HeadTooLarge);
}
#[test]
fn body_too_large() {
    let s = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
    assert_eq!(req(&s).unwrap_err(), ParseError::BodyTooLarge);
}
#[test]
fn bad_request_line_parts() {
    assert_eq!(req("GET /\r\n\r\n").unwrap_err(), ParseError::BadRequestLine);
}
#[test]
fn bad_version() {
    assert_eq!(req("GET / HTTP/2\r\n\r\n").unwrap_err(), ParseError::BadRequestLine);
}
#[test]
fn bad_method_token() {
    assert_eq!(req("G(T / HTTP/1.1\r\n\r\n").unwrap_err(), ParseError::BadRequestLine);
}
#[test]
fn path_must_be_origin_form() {
    assert_eq!(req("GET http://x/ HTTP/1.1\r\n\r\n").unwrap_err(), ParseError::BadRequestLine);
}
#[test]
fn non_ascii_head_rejected() {
    assert_eq!(req("GET /\u{e9} HTTP/1.1\r\n\r\n").unwrap_err(), ParseError::BadRequestLine);
}
#[test]
fn header_without_colon() {
    assert_eq!(req("GET / HTTP/1.1\r\nBroken\r\n\r\n").unwrap_err(), ParseError::BadHeader);
}
#[test]
fn obs_fold_rejected() {
    assert_eq!(req("GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n").unwrap_err(), ParseError::BadHeader);
}
#[test]
fn space_in_header_name_rejected() {
    assert_eq!(req("GET / HTTP/1.1\r\nX Y: a\r\n\r\n").unwrap_err(), ParseError::BadHeader);
}
#[test]
fn control_char_in_value_rejected() {
    assert_eq!(req("GET / HTTP/1.1\r\nX: a\u{1}b\r\n\r\n").unwrap_err(), ParseError::BadHeader);
}
#[test]
fn transfer_encoding_unsupported() {
    let e = req("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err();
    assert_eq!((e.clone(), e.status()), (ParseError::Unsupported, 501));
}
#[test]
fn negative_content_length() {
    assert_eq!(req("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n").unwrap_err(), ParseError::BadContentLength);
}
#[test]
fn conflicting_content_length() {
    assert_eq!(req("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab").unwrap_err(), ParseError::BadContentLength);
}
#[test]
fn same_content_length_twice_ok() {
    assert!(req("POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab").is_ok());
}
#[test]
fn pipelined_second_request_not_consumed() {
    let s = "GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
    let (r, n) = req(s).unwrap();
    assert_eq!(r.path, "/a");
    assert_eq!(&s[n..], "GET /b HTTP/1.1\r\n\r\n");
}
#[test]
fn response_roundtrip() {
    let mut h = mcpgw::gateway::Headers::new();
    h.insert("Mcp-Session-Id".into(), "s1".into());
    let bytes = write_response(200, &h, &json!({"ok": true}));
    let (st, hd, body) = parse_response(&bytes).unwrap();
    assert_eq!((st, hd["Mcp-Session-Id"].as_str()), (200, "s1"));
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"ok": true}));
}
#[test]
fn response_drops_crlf_header_values() {
    let mut h = mcpgw::gateway::Headers::new();
    h.insert("X-Evil".into(), "a\r\nSet-Cookie: x".into());
    let s = String::from_utf8(write_response(200, &h, &json!({}))).unwrap();
    assert!(!s.contains("Set-Cookie"));
}
#[test]
fn status_codes() {
    assert_eq!(ParseError::HeadTooLarge.status(), 431);
    assert_eq!(ParseError::BodyTooLarge.status(), 413);
    assert_eq!(ParseError::BadHeader.status(), 400);
    assert_eq!(http::reason(401), "Unauthorized");
}

// ------------------------------------------------------------------ real socket

const RESOURCE: &str = "https://gw.example/mcp";
const REDIRECT: &str = "http://127.0.0.1:8765/callback";

/// Build gateway + weather upstream inside the server thread; send the token back.
fn start() -> (http::ServerHandle, String) {
    let (tx, rx) = mpsc::channel();
    let srv = http::serve("127.0.0.1:0", move || {
        let clock: mcpgw::oauth::Clock = std::rc::Rc::new(|| 1_700_000_000.0);
        let mut auth = AuthorizationServer::new("https://auth.example", token_urlsafe(32).into_bytes(), clock.clone());
        auth.register_client("cli", &[REDIRECT], &["weather:read"]).unwrap();
        let v = token_urlsafe(40);
        let code = auth
            .authorize(AuthorizeRequest { client_id: "cli", redirect_uri: REDIRECT, scope: "weather:read", code_challenge: Some(&pkce_challenge(&v)), code_challenge_method: Some("S256"), resource: Some(RESOURCE) })
            .unwrap();
        let tok = auth
            .token(TokenRequest { grant_type: "authorization_code", client_id: "cli", code: Some(&code), code_verifier: Some(&v), redirect_uri: Some(REDIRECT), resource: Some(RESOURCE), ..Default::default() })
            .unwrap();
        let allow = Allowlist::new(vec![AllowEntry::new("weather", "https://weather.example", &[("get_forecast", &["weather:read"])])]);
        let mut gw = Gateway::new(RESOURCE, auth, allow, clock);
        gw.connect("weather", mocks::weather().shared()).unwrap();
        gw.approve("weather");
        tx.send(tok.access_token).unwrap();
        gw
    })
    .unwrap();
    let tok = rx.recv().unwrap();
    (srv, tok)
}

#[test]
fn full_flow_over_real_http() {
    let (srv, tok) = start();
    let bearer = format!("Bearer {tok}");
    let (st, _, b) = http::request(srv.addr, "GET", http::WELL_KNOWN, &[], None).unwrap();
    let prm: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((st, prm["resource"].as_str().unwrap()), (200, RESOURCE));
    let (st, h, init) = http::post_json(srv.addr, &[("Authorization", &bearer)], &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})).unwrap();
    assert_eq!(st, 200);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let sid = h["Mcp-Session-Id"].clone();
    let (_, _, out) = http::post_json(
        srv.addr,
        &[("Authorization", &bearer), ("Mcp-Session-Id", &sid), ("MCP-Protocol-Version", "2025-06-18")],
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "weather__get_forecast", "arguments": {"city": "Chicago"}}}),
    )
    .unwrap();
    assert_eq!(out["result"]["structuredContent"], json!({"temp_c": 21.5}));
    srv.shutdown();
}

#[test]
fn missing_bearer_gets_401_challenge_over_http() {
    let (srv, _) = start();
    let (st, h, _) = http::post_json(srv.addr, &[], &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"})).unwrap();
    assert_eq!(st, 401);
    assert!(h["WWW-Authenticate"].contains("resource_metadata="));
}

#[test]
fn bad_json_gets_parse_error() {
    let (srv, _) = start();
    let (st, _, b) = http::request(srv.addr, "POST", "/", &[], Some(b"{nope")).unwrap();
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((st, v["error"]["code"].as_i64()), (400, Some(-32700)));
}

#[test]
fn unknown_path_404_and_method_405() {
    let (srv, _) = start();
    assert_eq!(http::request(srv.addr, "GET", "/nope", &[], None).unwrap().0, 404);
    assert_eq!(http::request(srv.addr, "DELETE", "/", &[], None).unwrap().0, 405);
}

#[test]
fn chunked_request_gets_501() {
    let (srv, _) = start();
    assert_eq!(http::request(srv.addr, "POST", "/", &[("Transfer-Encoding", "chunked")], None).unwrap().0, 501);
}
