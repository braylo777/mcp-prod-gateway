//! Minimal OAuth 2.1 authorization server + resource-server token checks (port of `mcpgw/oauth.py`).
//!
//! PKCE S256 only · exact redirect match · RFC 8707 audience binding · single-use codes (replay
//! revokes) · rotating refresh tokens (reuse revokes the family) · RFC 8414 / RFC 9728 metadata.
//! Access tokens are HS256 JWTs; the bytes match the Python implementation.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canon;

pub type Clock = Rc<dyn Fn() -> f64>;
type HmacSha256 = Hmac<Sha256>;

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

pub fn pkce_challenge(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

pub fn token_urlsafe(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b64url(&b)
}

pub fn token_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub error: String,
    pub description: String,
}

impl OAuthError {
    pub fn new(error: &str, description: impl Into<String>) -> Self {
        OAuthError {
            error: error.into(),
            description: description.into(),
        }
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.description)
    }
}

impl std::error::Error for OAuthError {}

/// Python's `str(sorted(list_of_str))`, e.g. `['a', 'b']`.
fn py_list(items: &BTreeSet<String>) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", inner.join(", "))
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: HashSet<String>,
}

#[derive(Debug, Clone)]
struct Code {
    client_id: String,
    redirect_uri: String,
    scope: String,
    challenge: String,
    resource: String,
    expires_at: f64,
    used: bool,
    issued_jtis: Vec<String>,
}

#[derive(Debug, Clone)]
struct Refresh {
    family: String,
    client_id: String,
    scope: String,
    resource: String,
    active: bool,
}

#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
    pub jti: String,
}

pub fn sign_jwt(claims: &Value, key: &[u8]) -> String {
    let header =
        b64url(canon::dumps(&json!({"alg": "HS256", "typ": "JWT"}), false, true).as_bytes());
    let payload = b64url(canon::dumps(claims, true, true).as_bytes());
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(format!("{header}.{payload}").as_bytes());
    format!(
        "{header}.{payload}.{}",
        b64url(&mac.finalize().into_bytes())
    )
}

pub fn decode_jwt(token: &str, key: &[u8]) -> Result<Value, OAuthError> {
    let malformed = || OAuthError::new("invalid_token", "malformed token");
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(malformed());
    }
    let header: Value = b64url_decode(parts[0])
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(malformed)?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
        return Err(OAuthError::new("invalid_token", "unexpected alg"));
    }
    let sig =
        b64url_decode(parts[2]).ok_or_else(|| OAuthError::new("invalid_token", "bad signature"))?;
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| OAuthError::new("invalid_token", "bad signature"))?;
    b64url_decode(parts[1])
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(malformed)
}

fn redirect_ok(uri: &str) -> bool {
    uri.starts_with("https://")
        || uri.starts_with("http://127.0.0.1")
        || uri.starts_with("http://localhost")
}

pub struct AuthorizeRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub resource: Option<&'a str>,
}

#[derive(Default)]
pub struct TokenRequest<'a> {
    pub grant_type: &'a str,
    pub client_id: &'a str,
    pub code: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
}

pub struct AuthorizationServer {
    pub issuer: String,
    pub key: Vec<u8>,
    pub token_ttl: i64,
    pub code_ttl: f64,
    pub clock: Clock,
    pub clients: HashMap<String, Client>,
    codes: HashMap<String, Code>,
    refresh: HashMap<String, Refresh>,
    pub revoked_jtis: HashSet<String>,
    pub revoked_families: HashSet<String>,
}

impl AuthorizationServer {
    pub fn new(issuer: &str, signing_key: Vec<u8>, clock: Clock) -> Self {
        AuthorizationServer {
            issuer: issuer.into(),
            key: signing_key,
            token_ttl: 300,
            code_ttl: 60.0,
            clock,
            clients: HashMap::new(),
            codes: HashMap::new(),
            refresh: HashMap::new(),
            revoked_jtis: HashSet::new(),
            revoked_families: HashSet::new(),
        }
    }

    pub fn metadata(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{}/authorize", self.issuer),
            "token_endpoint": format!("{}/token", self.issuer),
            "registration_endpoint": format!("{}/register", self.issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        })
    }

    pub fn register_client(
        &mut self,
        client_id: &str,
        redirect_uris: &[&str],
        allowed_scopes: &[&str],
    ) -> Result<Client, OAuthError> {
        for uri in redirect_uris {
            if !redirect_ok(uri) {
                return Err(OAuthError::new("invalid_redirect_uri", *uri));
            }
        }
        let c = Client {
            client_id: client_id.into(),
            redirect_uris: redirect_uris.iter().map(|s| s.to_string()).collect(),
            allowed_scopes: allowed_scopes.iter().map(|s| s.to_string()).collect(),
        };
        self.clients.insert(client_id.into(), c.clone());
        Ok(c)
    }

    pub fn authorize(&mut self, r: AuthorizeRequest) -> Result<String, OAuthError> {
        let client = self
            .clients
            .get(r.client_id)
            .ok_or_else(|| OAuthError::new("unauthorized_client", "unknown client"))?;
        if !client.redirect_uris.iter().any(|u| u == r.redirect_uri) {
            return Err(OAuthError::new("invalid_request", "redirect_uri mismatch"));
        }
        let challenge = match r.code_challenge {
            Some(c) if !c.is_empty() => c,
            _ => {
                return Err(OAuthError::new(
                    "invalid_request",
                    "PKCE code_challenge required",
                ))
            }
        };
        if r.code_challenge_method != Some("S256") {
            return Err(OAuthError::new(
                "invalid_request",
                "only S256 PKCE is allowed",
            ));
        }
        let resource = match r.resource {
            Some(x) if !x.is_empty() => x,
            _ => {
                return Err(OAuthError::new(
                    "invalid_target",
                    "resource indicator required",
                ))
            }
        };
        let extra: BTreeSet<String> = r
            .scope
            .split_whitespace()
            .filter(|s| !client.allowed_scopes.contains(*s))
            .map(String::from)
            .collect();
        if !extra.is_empty() {
            return Err(OAuthError::new(
                "invalid_scope",
                format!("not allowed: {}", py_list(&extra)),
            ));
        }
        let code = token_urlsafe(24);
        let expires_at = (self.clock)() + self.code_ttl;
        self.codes.insert(
            code.clone(),
            Code {
                client_id: r.client_id.into(),
                redirect_uri: r.redirect_uri.into(),
                scope: r.scope.into(),
                challenge: challenge.into(),
                resource: resource.into(),
                expires_at,
                used: false,
                issued_jtis: vec![],
            },
        );
        Ok(code)
    }

    fn issue(
        &mut self,
        client_id: &str,
        scope: &str,
        resource: &str,
        family: &str,
    ) -> TokenResponse {
        let now = (self.clock)() as i64;
        let jti = token_hex(8);
        let access = sign_jwt(
            &json!({
                "iss": self.issuer, "aud": resource, "sub": client_id, "scope": scope,
                "iat": now, "exp": now + self.token_ttl, "jti": jti, "fam": family,
            }),
            &self.key,
        );
        let rt = token_urlsafe(24);
        self.refresh.insert(
            rt.clone(),
            Refresh {
                family: family.into(),
                client_id: client_id.into(),
                scope: scope.into(),
                resource: resource.into(),
                active: true,
            },
        );
        TokenResponse {
            access_token: access,
            token_type: "Bearer".into(),
            expires_in: self.token_ttl,
            refresh_token: rt,
            scope: scope.into(),
            jti,
        }
    }

    pub fn token(&mut self, r: TokenRequest) -> Result<TokenResponse, OAuthError> {
        match r.grant_type {
            "authorization_code" => {
                let now = (self.clock)();
                let code = r.code.unwrap_or("").to_string();
                let rec = self
                    .codes
                    .get(&code)
                    .cloned()
                    .ok_or_else(|| OAuthError::new("invalid_grant", "unknown code"))?;
                if rec.used {
                    // replay: revoke everything minted from this code
                    self.revoked_jtis.extend(rec.issued_jtis.iter().cloned());
                    return Err(OAuthError::new("invalid_grant", "code already used"));
                }
                if now > rec.expires_at {
                    return Err(OAuthError::new("invalid_grant", "code expired"));
                }
                if rec.client_id != r.client_id || Some(rec.redirect_uri.as_str()) != r.redirect_uri
                {
                    return Err(OAuthError::new(
                        "invalid_grant",
                        "client or redirect mismatch",
                    ));
                }
                match r.code_verifier {
                    Some(v) if !v.is_empty() && pkce_challenge(v) == rec.challenge => {}
                    _ => return Err(OAuthError::new("invalid_grant", "PKCE verification failed")),
                }
                if r.resource != Some(rec.resource.as_str()) {
                    return Err(OAuthError::new("invalid_target", "resource mismatch"));
                }
                self.codes.get_mut(&code).unwrap().used = true;
                let out = self.issue(r.client_id, &rec.scope, &rec.resource, &token_hex(6));
                self.codes
                    .get_mut(&code)
                    .unwrap()
                    .issued_jtis
                    .push(out.jti.clone());
                Ok(out)
            }
            "refresh_token" => {
                let key = r.refresh_token.unwrap_or("").to_string();
                let rec = match self.refresh.get(&key) {
                    Some(x) if x.client_id == r.client_id => x.clone(),
                    _ => return Err(OAuthError::new("invalid_grant", "unknown refresh token")),
                };
                if self.revoked_families.contains(&rec.family) {
                    return Err(OAuthError::new("invalid_grant", "token family revoked"));
                }
                if !rec.active {
                    self.revoked_families.insert(rec.family.clone());
                    return Err(OAuthError::new(
                        "invalid_grant",
                        "refresh token reuse detected; family revoked",
                    ));
                }
                self.refresh.get_mut(&key).unwrap().active = false;
                Ok(self.issue(r.client_id, &rec.scope, &rec.resource, &rec.family))
            }
            other => Err(OAuthError::new("unsupported_grant_type", other)),
        }
    }

    pub fn is_revoked(&self, claims: &Value) -> bool {
        let s = |k: &str| {
            claims
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        self.revoked_jtis.contains(&s("jti")) || self.revoked_families.contains(&s("fam"))
    }
}

pub struct VerifyParams<'a> {
    pub key: &'a [u8],
    pub issuer: &'a str,
    pub audience: &'a str,
    pub required_scopes: &'a [&'a str],
    pub now: f64,
    pub revocation: Option<&'a dyn Fn(&Value) -> bool>,
}

pub fn verify_access_token(token: &str, p: VerifyParams) -> Result<Value, OAuthError> {
    let claims = decode_jwt(token, p.key)?;
    if claims.get("iss").and_then(|v| v.as_str()) != Some(p.issuer) {
        return Err(OAuthError::new("invalid_token", "wrong issuer"));
    }
    if claims.get("aud").and_then(|v| v.as_str()) != Some(p.audience) {
        return Err(OAuthError::new(
            "invalid_token",
            "token audience is not this resource",
        ));
    }
    let exp = claims.get("exp").and_then(|v| v.as_f64()).unwrap_or(0.0);
    if p.now >= exp {
        return Err(OAuthError::new("invalid_token", "expired"));
    }
    if let Some(rev) = p.revocation {
        if rev(&claims) {
            return Err(OAuthError::new("invalid_token", "revoked"));
        }
    }
    let granted: HashSet<&str> = claims
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let missing: BTreeSet<String> = p
        .required_scopes
        .iter()
        .filter(|s| !granted.contains(**s))
        .map(|s| s.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(OAuthError::new(
            "insufficient_scope",
            format!("missing {}", py_list(&missing)),
        ));
    }
    Ok(claims)
}

/// RFC 9728 document served at `/.well-known/oauth-protected-resource`.
pub fn protected_resource_metadata(
    resource: &str,
    authorization_servers: &[String],
    scopes: &[String],
) -> Value {
    json!({
        "resource": resource,
        "authorization_servers": authorization_servers,
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
    })
}
