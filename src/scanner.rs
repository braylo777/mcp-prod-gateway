//! Supply-chain scanner for MCP tool definitions (port of `mcpgw/scanner.py`).
//!
//! TP* tool poisoning · RP* rug pull (fingerprint drift) · SC* over-broad scopes.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};
use base64::Engine;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canon;

pub const HIGH: &str = "high";
pub const MEDIUM: &str = "medium";
pub const LOW: &str = "low";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: String,
    pub tool: String,
    pub detail: String,
}

impl Finding {
    pub fn new(rule: &str, severity: &str, tool: &str, detail: String) -> Self {
        Finding {
            rule: rule.into(),
            severity: severity.into(),
            tool: tool.into(),
            detail,
        }
    }
}

/// sha256 over the canonical JSON of every field a model or user would rely on.
pub fn fingerprint(tool: &Value) -> String {
    let mut material = Map::new();
    for k in [
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
    ] {
        material.insert(k.into(), tool.get(k).cloned().unwrap_or(Value::Null));
    }
    let s = canon::dumps(&Value::Object(material), true, true);
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn texts(v: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Object(m) => {
            for (k, x) in m {
                if k == "name" && path.is_empty() {
                    continue;
                }
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                texts(x, &p, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                texts(x, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        pub(crate) static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

re!(
    TAGS,
    r"(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>|\[/?INST\]"
);
re!(
    OVERRIDE,
    concat!(
        r"(?i)ignore (all |any )?(previous|prior|above|other) (instructions|rules)",
        r"|(do not|don't|never) (tell|inform|mention|reveal|show)[^.]{0,40}\buser",
        r"|without (telling|informing|notifying|alerting) the user",
        r"|before (using|calling) this tool,? (you must|always|first)",
        r"|you (must|should) (first )?(read|call|send|include|pass)",
        r"|this is (very )?important[^.]{0,30}(otherwise|or else|the tool will)",
        r"|(the user|they) (won't|will not|must not) (see|notice)"
    )
);
re!(
    SECRETS,
    concat!(
        r"(?i)~/\.ssh|id_rsa|id_ed25519|\.env\b|mcp\.json|claude_desktop_config|/etc/passwd",
        r"|\.aws/credentials|private key|api[_ ]?keys?\b|access tokens?\b|seed phrase"
    )
);
re!(
    INVISIBLE,
    r"[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}\x{E0000}-\x{E007F}]"
);
re!(URL, r#"https?://[^\s"')]+|\b[\w.+-]+@[\w-]+\.[\w.]+\b"#);
re!(
    EXFIL_VERB,
    r"(?i)\b(send|post|forward|upload|exfiltrate|copy|bcc|cc|report)\b"
);
re!(B64, r"[A-Za-z0-9+/]{40,}={0,2}");
re!(
    SMUGGLE_PARAM,
    r"(?i)^(note|notes|sidenote|side_note|context|reasoning|metadata|extra|debug|feedback)$"
);
re!(
    SMUGGLE_DESC,
    r"(?i)(conversation|chat history|previous messages|system prompt|file contents|all (the )?(text|content))"
);
re!(
    DANGEROUS_PARAM,
    r"(?i)^(command|cmd|shell|script|sql|query_raw|exec|code|path|file_path|url)$"
);
re!(WILDCARD, r"(?i)^\*$|:\*$|^all$|^.*:all$");
re!(
    ADMIN,
    r"(?i)(^|[:.])(admin|root|owner|superuser|full_access|repo)$|^(files|fs|db|mail):write$"
);
re!(WRITE, r"(?i)(write|delete|admin|send|exec|modify)");

const B64_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// Mirrors `base64.b64decode(m + "=" * pad).decode("ascii").isprintable()`.
fn printable_base64(m: &str) -> bool {
    let body = m.trim_end_matches('=');
    if body.len() % 4 == 1 {
        return false;
    }
    match B64_LENIENT.decode(body) {
        Ok(bytes) => bytes.iter().all(|b| (0x20..=0x7e).contains(b)),
        Err(_) => false,
    }
}

fn tool_name(tool: &Value) -> String {
    match tool.get("name") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "?".into(),
    }
}

fn properties(tool: &Value) -> Vec<(String, Value)> {
    tool.get("inputSchema")
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|x| x != 0.0).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

thread_local! {
    static WORD_RE: std::cell::RefCell<std::collections::HashMap<String, Regex>> = Default::default();
}

/// `\b{escaped name}\b`, compiled once per thread per name (bounded at 4096 entries).
pub(crate) fn word_regex(name: &str) -> Regex {
    WORD_RE.with(|c| {
        let mut m = c.borrow_mut();
        if let Some(r) = m.get(name) {
            return r.clone();
        }
        if m.len() >= 4096 {
            m.clear();
        }
        let r = Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap();
        m.insert(name.to_string(), r.clone());
        r
    })
}

pub fn scan_poisoning(tool: &Value, known_tool_names: &HashSet<String>) -> Vec<Finding> {
    let name = tool_name(tool);
    let mut found = Vec::new();
    let mut rest = Map::new();
    if let Some(obj) = tool.as_object() {
        for (k, v) in obj {
            if k != "name" {
                rest.insert(k.clone(), v.clone());
            }
        }
    }
    let mut ts = Vec::new();
    texts(&Value::Object(rest), "", &mut ts);
    let joined = ts
        .iter()
        .map(|(_, t)| t.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for (path, text) in &ts {
        if TAGS.is_match(text) {
            found.push(Finding::new(
                "TP001",
                HIGH,
                &name,
                format!("hidden-instruction tag in {path}"),
            ));
        }
        if OVERRIDE.is_match(text) {
            found.push(Finding::new(
                "TP002",
                HIGH,
                &name,
                format!("instruction-override phrasing in {path}"),
            ));
        }
        if SECRETS.is_match(text) {
            found.push(Finding::new(
                "TP003",
                HIGH,
                &name,
                format!("reference to credentials/sensitive files in {path}"),
            ));
        }
        if INVISIBLE.is_match(text) {
            found.push(Finding::new(
                "TP004",
                HIGH,
                &name,
                format!("invisible/bidi unicode in {path}"),
            ));
        }
        if URL.is_match(text) && EXFIL_VERB.is_match(text) {
            found.push(Finding::new(
                "TP006",
                MEDIUM,
                &name,
                format!("exfiltration sink (URL/email + send verb) in {path}"),
            ));
        }
        if B64.find_iter(text).any(|m| printable_base64(m.as_str())) {
            found.push(Finding::new(
                "TP007",
                MEDIUM,
                &name,
                format!("base64-encoded text in {path}"),
            ));
        }
    }
    let mut others: Vec<&String> = known_tool_names.iter().filter(|n| **n != name).collect();
    others.sort();
    for other in others {
        if word_regex(other).is_match(&joined) {
            found.push(Finding::new(
                "TP005",
                HIGH,
                &name,
                format!("description references other tool '{other}' (shadowing)"),
            ));
        }
    }
    for (pname, spec) in properties(tool) {
        let desc = spec
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        if SMUGGLE_PARAM.is_match(&pname) && SMUGGLE_DESC.is_match(desc) {
            found.push(Finding::new(
                "TP008",
                HIGH,
                &name,
                format!("parameter '{pname}' asks for conversation/file content"),
            ));
        }
    }
    // dedupe by (rule, detail), keeping first position like a Python dict
    let mut seen = HashSet::new();
    found.retain(|f| seen.insert((f.rule.clone(), f.detail.clone())));
    found
}

pub fn scan_scopes(tool: &Value, scopes: &[String]) -> Vec<Finding> {
    let name = tool_name(tool);
    let mut found = Vec::new();
    for s in scopes {
        if WILDCARD.is_match(s) {
            found.push(Finding::new(
                "SC001",
                HIGH,
                &name,
                format!("wildcard scope '{s}'"),
            ));
        } else if ADMIN.is_match(s) {
            found.push(Finding::new(
                "SC002",
                MEDIUM,
                &name,
                format!("broad scope '{s}'"),
            ));
        }
    }
    let read_only = truthy(tool.get("annotations").and_then(|a| a.get("readOnlyHint")));
    if read_only && scopes.iter().any(|s| WRITE.is_match(s)) {
        found.push(Finding::new(
            "SC003",
            HIGH,
            &name,
            "readOnlyHint tool requests write/delete scopes".into(),
        ));
    }
    for (pname, spec) in properties(tool) {
        let ty = spec
            .get("type")
            .cloned()
            .unwrap_or(Value::String("string".into()));
        let constrained = ["enum", "pattern", "const", "maxLength", "format"]
            .iter()
            .any(|k| spec.get(*k).is_some());
        if DANGEROUS_PARAM.is_match(&pname) && ty == Value::String("string".into()) && !constrained
        {
            found.push(Finding::new(
                "SC004",
                MEDIUM,
                &name,
                format!("unconstrained dangerous parameter '{pname}'"),
            ));
        }
    }
    found
}

/// `approved`: tool name -> fingerprint captured at approval time.
pub fn diff_against_approved(
    current: &[Value],
    approved: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut found = Vec::new();
    let mut names = HashSet::new();
    for tool in current {
        let n = tool_name(tool);
        names.insert(n.clone());
        match approved.get(&n) {
            None => found.push(Finding::new(
                "RP002",
                MEDIUM,
                &n,
                "tool added after approval; needs re-approval".into(),
            )),
            Some(fp) if *fp != fingerprint(tool) => found.push(Finding::new(
                "RP001",
                HIGH,
                &n,
                "tool definition changed after approval (rug pull)".into(),
            )),
            _ => {}
        }
    }
    for n in approved.keys() {
        if !names.contains(n) {
            found.push(Finding::new(
                "RP003",
                LOW,
                n,
                "approved tool disappeared".into(),
            ));
        }
    }
    found
}

pub fn scan_server(
    tools: &[Value],
    scopes_by_tool: &BTreeMap<String, Vec<String>>,
) -> Vec<Finding> {
    let names: HashSet<String> = tools.iter().map(tool_name).collect();
    let mut out = Vec::new();
    for t in tools {
        out.extend(scan_poisoning(t, &names));
        let scopes = scopes_by_tool
            .get(&tool_name(t))
            .cloned()
            .unwrap_or_default();
        out.extend(scan_scopes(t, &scopes));
    }
    out
}
