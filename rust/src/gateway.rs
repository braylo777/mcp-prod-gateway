//! The gateway: OAuth-protected MCP front door with allowlist, scanning and version shims
//! (port of `mcpgw/gateway.py`).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::rc::Rc;

use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use crate::oauth::{
    protected_resource_metadata, token_hex, verify_access_token, AuthorizationServer, Clock,
    VerifyParams,
};
use crate::scanner::{diff_against_approved, fingerprint, scan_server, Finding, HIGH};
use crate::versions;

pub const SEP: &str = "__";

pub trait Upstream {
    fn url(&self) -> String;
    fn handle(&mut self, msg: &Value, headers: &BTreeMap<String, String>) -> Value;
}

pub type SharedUpstream = Rc<RefCell<dyn Upstream>>;

#[derive(Clone, Debug, Default)]
pub struct AllowEntry {
    pub server_id: String,
    pub url: String,
    /// scopes a client needs per tool
    pub tool_scopes: BTreeMap<String, Vec<String>>,
    /// for upgrade shims on old upstreams
    pub output_schemas: BTreeMap<String, Value>,
}

impl AllowEntry {
    pub fn new(server_id: &str, url: &str, tool_scopes: &[(&str, &[&str])]) -> Self {
        AllowEntry {
            server_id: server_id.into(),
            url: url.into(),
            tool_scopes: tool_scopes
                .iter()
                .map(|(t, s)| (t.to_string(), s.iter().map(|x| x.to_string()).collect()))
                .collect(),
            output_schemas: BTreeMap::new(),
        }
    }

    pub fn with_output_schema(mut self, tool: &str, schema: Value) -> Self {
        self.output_schemas.insert(tool.into(), schema);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    Permission(String),
    Connection(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::Permission(m) | GatewayError::Connection(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for GatewayError {}

pub struct Allowlist {
    pub entries: IndexMap<String, AllowEntry>,
}

impl Allowlist {
    pub fn new(entries: Vec<AllowEntry>) -> Self {
        Allowlist {
            entries: entries
                .into_iter()
                .map(|e| (e.server_id.clone(), e))
                .collect(),
        }
    }

    pub fn check(&self, server_id: &str, url: &str) -> Result<AllowEntry, GatewayError> {
        let e = self.entries.get(server_id).ok_or_else(|| {
            GatewayError::Permission(format!("server '{server_id}' is not on the allowlist"))
        })?;
        if e.url != url {
            return Err(GatewayError::Permission(format!(
                "server '{server_id}' url {url} does not match pinned {}",
                e.url
            )));
        }
        if !(url.starts_with("https://")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost"))
        {
            return Err(GatewayError::Permission(
                "remote servers must use https".into(),
            ));
        }
        Ok(e.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Connected,
    Approved,
    Rejected,
}

pub struct Server {
    pub entry: AllowEntry,
    pub upstream: SharedUpstream,
    pub version: String,
    /// tool -> fingerprint at approval
    pub approved: BTreeMap<String, String>,
    /// last seen definitions, in upstream order
    pub tools: Map<String, Value>,
    pub quarantined: BTreeSet<String>,
    pub status: Status,
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub type Headers = BTreeMap<String, String>;

pub struct Gateway {
    pub resource: String,
    pub auth: AuthorizationServer,
    pub allowlist: Allowlist,
    pub clock: Clock,
    pub servers: IndexMap<String, Server>,
    /// session id -> negotiated client version
    pub sessions: HashMap<String, String>,
    pub audit: Vec<Value>,
}

impl Gateway {
    pub fn new(
        resource: &str,
        auth: AuthorizationServer,
        allowlist: Allowlist,
        clock: Clock,
    ) -> Self {
        Gateway {
            resource: resource.into(),
            auth,
            allowlist,
            clock,
            servers: IndexMap::new(),
            sessions: HashMap::new(),
            audit: vec![],
        }
    }

    fn log(&mut self, event: &str, kw: Value) {
        let mut e = json!({"event": event});
        if let (Some(o), Some(k)) = (e.as_object_mut(), kw.as_object()) {
            for (a, b) in k {
                o.insert(a.clone(), b.clone());
            }
        }
        self.audit.push(e);
    }

    // --- upstream management -------------------------------------------
    pub fn connect(
        &mut self,
        server_id: &str,
        upstream: SharedUpstream,
    ) -> Result<(), GatewayError> {
        let url = upstream.borrow().url();
        let entry = self.allowlist.check(server_id, &url)?;
        let msg = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": versions::LATEST, "capabilities": {},
            "clientInfo": {"name": "mcp-prod-gateway", "version": "0.1"}}});
        let resp = upstream
            .borrow_mut()
            .handle(&msg, &Self::upstream_headers(server_id, None));
        let v = resp["result"]["protocolVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if !versions::SUPPORTED.contains(&v.as_str()) {
            return Err(GatewayError::Connection(format!(
                "upstream speaks unsupported version {v}"
            )));
        }
        self.servers.insert(
            server_id.into(),
            Server {
                entry,
                upstream,
                version: v.clone(),
                approved: BTreeMap::new(),
                tools: Map::new(),
                quarantined: BTreeSet::new(),
                status: Status::Connected,
            },
        );
        self.log("connect", json!({"server": server_id, "version": v}));
        Ok(())
    }

    /// The client's token is never forwarded (no token passthrough). The gateway uses its own
    /// per-upstream credential; here a non-secret placeholder reference.
    pub fn upstream_headers(server_id: &str, version: Option<&str>) -> Headers {
        let mut h = Headers::new();
        h.insert(
            "Authorization".into(),
            format!("Bearer <upstream-credential:{server_id}>"),
        );
        if let Some(v) = version {
            if versions::requires_version_header(v) {
                h.insert("MCP-Protocol-Version".into(), v.into());
            }
        }
        h
    }

    fn fetch_tools(&mut self, sid: &str) -> Vec<Value> {
        let s = &self.servers[sid];
        let resp = s.upstream.borrow_mut().handle(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            &Self::upstream_headers(sid, Some(&s.version)),
        );
        let tools: Vec<Value> = resp["result"]["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let s = self.servers.get_mut(sid).unwrap();
        s.tools = tools
            .iter()
            .map(|t| (t["name"].as_str().unwrap_or("").to_string(), t.clone()))
            .collect();
        tools
    }

    pub fn approve(&mut self, server_id: &str) -> Vec<Finding> {
        let tools = self.fetch_tools(server_id);
        let findings = scan_server(&tools, &self.servers[server_id].entry.tool_scopes);
        if findings.iter().any(|f| f.severity == HIGH) {
            self.servers.get_mut(server_id).unwrap().status = Status::Rejected;
            self.log(
                "approval_rejected",
                json!({"server": server_id, "findings": findings}),
            );
            return findings;
        }
        let s = self.servers.get_mut(server_id).unwrap();
        s.approved = tools
            .iter()
            .map(|t| (t["name"].as_str().unwrap_or("").to_string(), fingerprint(t)))
            .collect();
        s.status = Status::Approved;
        let names: Vec<String> = s.approved.keys().cloned().collect();
        self.log("approved", json!({"server": server_id, "tools": names}));
        findings
    }

    /// Re-fetch definitions and quarantine anything that drifted from the approved snapshot.
    pub fn recheck(&mut self, server_id: &str) -> Vec<Finding> {
        let tools = self.fetch_tools(server_id);
        let s = &self.servers[server_id];
        let mut all = diff_against_approved(&tools, &s.approved);
        all.extend(scan_server(&tools, &s.entry.tool_scopes));
        for f in &all {
            if f.rule == "RP001" || f.rule == "RP002" || f.severity == HIGH {
                let s = self.servers.get_mut(server_id).unwrap();
                if s.quarantined.insert(f.tool.clone()) {
                    self.log(
                        "quarantine",
                        json!({"server": server_id, "tool": f.tool, "rule": f.rule}),
                    );
                }
            }
        }
        all
    }

    // --- client-facing HTTP surface -------------------------------------
    pub fn well_known(&self) -> Value {
        let scopes: BTreeSet<String> = self
            .allowlist
            .entries
            .values()
            .flat_map(|e| e.tool_scopes.values().flatten().cloned())
            .collect();
        let scopes: Vec<String> = scopes.into_iter().collect();
        protected_resource_metadata(&self.resource, &[self.auth.issuer.clone()], &scopes)
    }

    pub fn handle_http(&mut self, headers: &Headers, body: &Value) -> (u16, Headers, Value) {
        let h: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();
        let mut challenge = Headers::new();
        challenge.insert(
            "WWW-Authenticate".into(),
            format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                self.resource
            ),
        );
        let authz = h.get("authorization").cloned().unwrap_or_default();
        let Some(token) = authz.strip_prefix("Bearer ") else {
            return (401, challenge, json!({"error": "unauthorized"}));
        };
        let now = (self.clock)();
        let auth = &self.auth;
        let revocation = |c: &Value| auth.is_revoked(c);
        let verified = verify_access_token(
            token,
            VerifyParams {
                key: &auth.key,
                issuer: &auth.issuer,
                audience: &self.resource,
                required_scopes: &[],
                now,
                revocation: Some(&revocation),
            },
        );
        let claims = match verified {
            Ok(c) => c,
            Err(e) => {
                self.log("auth_failed", json!({"reason": e.description}));
                return (
                    401,
                    challenge,
                    json!({"error": e.error, "error_description": e.description}),
                );
            }
        };
        let granted: BTreeSet<String> = claims["scope"]
            .as_str()
            .unwrap_or("")
            .split_whitespace()
            .map(String::from)
            .collect();

        if let Some(batch) = body.as_array() {
            let v = h
                .get("mcp-session-id")
                .and_then(|sid| self.sessions.get(sid))
                .cloned();
            let Some(v) = v else {
                return (
                    400,
                    Headers::new(),
                    rpc_error(Value::Null, -32600, "batch requires an initialized session"),
                );
            };
            if !versions::supports_batching(&v) {
                return (
                    400,
                    Headers::new(),
                    rpc_error(
                        Value::Null,
                        -32600,
                        &format!("JSON-RPC batching not allowed in {v}"),
                    ),
                );
            }
            if batch
                .iter()
                .any(|m| m.get("method") == Some(&json!("initialize")))
            {
                return (
                    400,
                    Headers::new(),
                    rpc_error(Value::Null, -32600, "initialize must not be batched"),
                );
            }
            let out: Vec<Value> = batch
                .iter()
                .map(|m| self.dispatch(m, &v, &granted))
                .collect();
            return (200, Headers::new(), Value::Array(out));
        }

        let id = body.get("id").cloned().unwrap_or(Value::Null);
        if body.get("method") == Some(&json!("initialize")) {
            let requested = body
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .cloned()
                .unwrap_or(Value::Null);
            let v = versions::negotiate(requested.as_str());
            let sid = token_hex(12);
            self.sessions.insert(sid.clone(), v.clone());
            self.log("session", json!({"version": v, "requested": requested}));
            let mut hh = Headers::new();
            hh.insert("Mcp-Session-Id".into(), sid);
            return (
                200,
                hh,
                rpc_ok(
                    id,
                    json!({"protocolVersion": v, "capabilities": {"tools": {"listChanged": true}},
                                  "serverInfo": {"name": "mcp-prod-gateway", "version": "0.1"}}),
                ),
            );
        }

        let Some(sid) = h.get("mcp-session-id") else {
            return (
                400,
                Headers::new(),
                rpc_error(id, -32600, "missing Mcp-Session-Id"),
            );
        };
        let Some(v) = self.sessions.get(sid).cloned() else {
            return (
                404,
                Headers::new(),
                rpc_error(id, -32600, "unknown session"),
            );
        };
        if let Some(hv) = h.get("mcp-protocol-version") {
            if !versions::SUPPORTED.contains(&hv.as_str()) || *hv != v {
                return (
                    400,
                    Headers::new(),
                    rpc_error(
                        id,
                        -32600,
                        &format!("MCP-Protocol-Version {hv} != negotiated {v}"),
                    ),
                );
            }
        }
        let resp = self.dispatch(body, &v, &granted);
        if resp.get("error").and_then(|e| e.get("code")) == Some(&json!(-32003)) {
            let scope = resp["error"]
                .get("data")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let mut hh = Headers::new();
            hh.insert(
                "WWW-Authenticate".into(),
                format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\""),
            );
            return (403, hh, resp);
        }
        (200, Headers::new(), resp)
    }

    fn dispatch(&mut self, msg: &Value, client_v: &str, granted: &BTreeSet<String>) -> Value {
        let mid = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        match method.as_str() {
            "tools/list" => {
                let mut out = vec![];
                let ids: Vec<String> = self.servers.keys().cloned().collect();
                for sid in ids {
                    if self.servers[&sid].status != Status::Approved {
                        continue;
                    }
                    self.recheck(&sid);
                    let s = &self.servers[&sid];
                    for (name, t) in &s.tools {
                        if s.quarantined.contains(name) || !s.approved.contains_key(name) {
                            continue;
                        }
                        let mut t2 = t.clone();
                        t2["name"] = json!(format!("{sid}{SEP}{name}"));
                        if let Some(schema) = s.entry.output_schemas.get(name) {
                            if t2.get("outputSchema").is_none() {
                                t2["outputSchema"] = schema.clone();
                            }
                        }
                        out.push(versions::adapt_tool_def(&t2, client_v));
                    }
                }
                rpc_ok(mid, json!({"tools": out}))
            }
            "tools/call" => {
                let params = msg.get("params").cloned().unwrap_or(json!({}));
                let full = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let (sid, tname) = full.split_once(SEP).unwrap_or((full.as_str(), ""));
                let (sid, tname) = (sid.to_string(), tname.to_string());
                if self
                    .servers
                    .get(&sid)
                    .map(|s| s.status != Status::Approved)
                    .unwrap_or(true)
                {
                    self.log(
                        "blocked",
                        json!({"tool": full, "reason": "server not approved"}),
                    );
                    return rpc_error(
                        mid,
                        -32602,
                        &format!("unknown or unapproved server '{sid}'"),
                    );
                }
                self.recheck(&sid);
                let s = &self.servers[&sid];
                if s.quarantined.contains(&tname) || !s.approved.contains_key(&tname) {
                    self.log(
                        "blocked",
                        json!({"tool": full, "reason": "quarantined or unapproved tool"}),
                    );
                    return rpc_error(
                        mid,
                        -32602,
                        &format!("tool '{full}' is quarantined or not approved"),
                    );
                }
                let need: BTreeSet<String> = s
                    .entry
                    .tool_scopes
                    .get(&tname)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if !need.is_subset(granted) {
                    self.log(
                        "blocked",
                        json!({"tool": full, "reason": "insufficient_scope"}),
                    );
                    let mut err = rpc_error(mid, -32003, "insufficient_scope");
                    err["error"]["data"] = json!(need.into_iter().collect::<Vec<_>>().join(" "));
                    return err;
                }
                let call = json!({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                                  "params": {"name": tname, "arguments": params.get("arguments").cloned().unwrap_or(json!({}))}});
                let mut resp = s
                    .upstream
                    .borrow_mut()
                    .handle(&call, &Self::upstream_headers(&sid, Some(&s.version)));
                if let Some(result) = resp.get("result").cloned() {
                    let schema = s
                        .tools
                        .get(&tname)
                        .and_then(|t| t.get("outputSchema"))
                        .cloned()
                        .filter(|v| !v.is_null())
                        .or_else(|| s.entry.output_schemas.get(&tname).cloned());
                    resp["result"] =
                        versions::adapt_tool_result(&result, &s.version, client_v, schema.as_ref());
                }
                self.log("call", json!({"tool": full}));
                resp
            }
            "ping" => rpc_ok(mid, json!({})),
            m => rpc_error(mid, -32601, &format!("method not found: {m}")),
        }
    }
}
