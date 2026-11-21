//! Policy layer (Rust only): v1 rules from [`crate::scanner`] plus deep rules on normalized text.
//!
//! The v1 functions stay byte-for-byte equal to the Python reference (see `tests/parity*.rs`).
//! This module adds rules that the reference does not have:
//!
//! | Rule  | Sev  | What it catches |
//! |-------|------|-----------------|
//! | TP009 | high | v1 tag/override/secret text that only matches after normalization (homoglyphs, leet, spaced letters, fullwidth, combining marks, soft hyphens) |
//! | TP010 | high | covert-action paraphrase ("quietly append the user's saved passwords") |
//! | TP011 | high | confused-deputy chain: tells the model to call a privileged tool or act with elevated rights |
//! | TP012 | high | prompt-injection markers (role tokens, "disregard previous", "developer mode") |
//! | TP013 | high | instruction hidden in a schema property *name* |
//! | TP014 | high | encoded payload (short/url-safe base64, hex, percent) that decodes to an instruction |
//! | TP015 | med  | obfuscated exfil sink (`hxxp`, `[.]`, "at … dot") with a send verb |
//! | TP016 | high | any parameter whose description asks for the conversation, prompt or secrets |
//! | SH001 | high | typosquat of a tool on another server (`send_emai1`, `sendEmail`) |
//! | SH002 | low  | exact name collision with a tool on another server (namespacing defuses it) |
//!
//! It also refines TP005: a reference to a tool on the *same* server is LOW unless the text
//! hooks it ("when X is used", "instead of X", "before X"). References to other servers stay HIGH.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use base64::Engine;
use regex::Regex;
use serde_json::Value;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::scanner::{scan_poisoning, scan_scopes, Finding, EXFIL_VERB, HIGH, LOW, MEDIUM, SECRETS, URL};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

// v1 patterns, applied again after normalization (lower-case, ASCII-folded text).
re!(
    N_TAGS,
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>|\[/?inst\]"
);
re!(
    N_OVERRIDE,
    concat!(
        r"ignore (all |any )?(previous|prior|above|other) (instructions|rules)",
        r"|(do not|dont|never) (tell|inform|mention|reveal|show)[^.]{0,40}\buser",
        r"|without (telling|informing|notifying|alerting) the user",
        r"|before (using|calling) this tool,? (you must|always|first)",
        r"|you (must|should) (first )?(read|call|send|include|pass)",
        r"|(the user|they) (wont|will not|must not) (see|notice)"
    )
);
re!(
    N_SECRETS,
    concat!(
        r"~/\.ssh|id rsa|id_rsa|id ed25519|id_ed25519|\.env\b|mcp\.json|claude desktop config",
        r"|/etc/passwd|\.aws/credentials|private key|seed phrase"
    )
);
re!(
    COVERT,
    concat!(
        r"\b(quietly|silently|secretly|discreetly|covertly|stealthily|invisibly)\b[^.]{0,80}",
        r"\b(append|attach|include|add|copy|forward|embed|send|upload|post|log|store|save|collect|read|grab|leak|share)\b",
        r"|\b(in the background|behind the scenes|under the hood),? (also )?(append|attach|include|copy|forward|send|upload|collect|read)",
        r"|without (the user|them|anyone) (knowing|noticing|seeing|being told)",
        r"|keep (this|it) (secret|hidden|between us|confidential) from the user",
        r"|(the user|they) (does not|doesnt|do not|dont) need to (know|be told|see)",
        r"|(do not|dont|never) (mention|bring up|disclose|surface|log|display) (this|these|that)",
        r"|no need to (tell|inform|ask|notify) the user"
    )
);
re!(
    SENSITIVE,
    concat!(
        r"passwords?|passcodes?|cookies?|session (tokens?|ids?)|credit card|card numbers?|cvv",
        r"|ssh keys?|private notes|chat history|conversation|contacts?|address book|keychain",
        r"|credentials?|secrets?|tokens?|api keys?|2fa|mfa|backup codes|wallet|seed"
    )
);
re!(
    DEPUTY,
    concat!(
        r"\b(then|also|afterwards|after that|next|finally|and)\b,? (immediately )?(call|invoke|use|run|trigger|execute)\b[^.]{0,60}",
        r"\b(delete|drop|destroy|wipe|transfer|wire|pay|refund|grant|elevate|promote|approve|merge|deploy|publish|rotate|revoke|disable|purge|force.?push|chmod|sudo|admin)",
        r"|\b(using|with|use) ((your|its) (elevated|admin|root|service|full) |the gateway'?s? |(elevated|admin|root|service) )(credentials|privileges|permissions|access|token|rights)",
        r"|on (the user'?s?|their) behalf,? (approve|delete|transfer|grant|merge|pay|send|sign)",
        r"|\bpass (the )?(result|output|response|token|it) (on )?to [`'\x22]?\w*(admin|delete|transfer|grant|exec|shell|deploy|payment)"
    )
);
re!(
    INJECT,
    concat!(
        r"<\|im_(start|end)\|>|<\|(system|assistant|user|endoftext)\|>|(^|\n|[.!?]\s)\s*#{0,3}\s*(system|assistant|developer)\s*:",
        r"|\bnew (system )?(instructions|rules|directives)\s*:|begin (system|admin|developer|root) (prompt|message|instructions)",
        r"|\bdeveloper mode\b|\bjailbreak|\bdan mode\b|you are now (in |an? |the |no longer )",
        r"|disregard (the |all |any |your )?(above|previous|prior|earlier|safety|system|other)",
        r"|forget (everything|all|your|the) (above|previous|prior|earlier|instructions|rules)",
        r"|override (your|all|the|any) (instructions|guidelines|safety|rules|policies)",
        r"|(end|ignore) of (the )?(tool )?(description|context)\W+(now|new)"
    )
);
re!(
    HOOK,
    r"(?i)\b(when|whenever|each time|every time|before|after|instead of|rather than|replaces?|deprecated)\b"
);
re!(
    OBF_SINK,
    r"hxxps?://|\w\[\.\]\w|\w\(\.\)\w|\w ?(\[at\]|\(at\)|\{at\}) ?\w|\w+ at [\w-]+ dot (com|net|org|io|example|ru|xyz)"
);
re!(
    SEND_VERB,
    r"\b(send|post|forward|upload|exfiltrate|copy|bcc|cc|report|mail|ship|beam|push)\b"
);
re!(
    PARAM_ASK,
    concat!(
        r"\b(paste|include|provide|copy|put|fill|insert|dump|attach|add|place|echo|supply)\b[^.]{0,50}",
        r"(conversation|chat history|chat log|previous messages|prior messages|system prompt|transcript|everything the user|all (the )?messages",
        r"|passwords?|credentials?|api keys?|secret|tokens?|private key|cookies?|ssh",
        r"|(file contents|files?) (you|the assistant|the model) (have|has) (already )?(read|seen|opened))"
    )
);
re!(SENT_SPLIT, r"[.!?](?:\s+|$)|\n");
re!(
    SAFE_HANDLING,
    concat!(
        r"(do not|dont|never|no need to) (pass|send|include|provide|share|put|enter|paste)\b",
        r"|(handled|configured|stored|managed|kept) (by|on) the server|server side",
        r"|no (api )?(keys?|tokens?) (are|is) (needed|required)|(are|is) not (needed|required)"
    )
);
re!(B64ISH, r"[A-Za-z0-9+/_-]{16,}={0,2}");
re!(HEXISH, r"\b(?:[0-9a-fA-F]{2}){12,}\b");
re!(PCT, r"(?:%[0-9a-fA-F]{2}){4,}");

/// Fold a string so that obfuscated text matches plain-text rules.
///
/// NFKC → drop combining marks, invisible/bidi chars and soft hyphens → homoglyphs to Latin →
/// lower-case → leet inside mixed tokens → join spaced-out letters → `_` and `-` between
/// letters to space / nothing → collapse whitespace.
pub fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.nfkd() {
        if is_combining_mark(c) || is_invisible(c) {
            continue;
        }
        out.push(homoglyph(c));
    }
    let lowered: String = out.nfkc().collect::<String>().to_lowercase();
    let deleet = deleet(&lowered);
    let joined = join_spaced(&deleet);
    // separators between letters
    let chars: Vec<char> = joined.chars().collect();
    let mut s2 = String::with_capacity(joined.len());
    for (i, &c) in chars.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1).copied();
        let between =
            prev.is_some_and(|p| p.is_alphabetic()) && next.is_some_and(|n| n.is_alphabetic());
        match c {
            '_' => s2.push(' '),
            '-' | '*' | '|' | '·' if between => {}
            '\'' | '’' if between => {}
            _ => s2.push(c),
        }
    }
    s2.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064
        | 0x2066..=0x2069 | 0xFEFF | 0xE0000..=0xE007F)
}

fn homoglyph(c: char) -> char {
    match c {
        'а' | 'α' | 'ɑ' => 'a',
        'А' | 'Α' => 'A',
        'в' | 'β' => 'b',
        'В' | 'Β' => 'B',
        'с' | 'ϲ' => 'c',
        'С' | 'Ϲ' => 'C',
        'ԁ' => 'd',
        'е' | 'ε' | 'ё' => 'e',
        'Е' | 'Ε' | 'Ё' => 'E',
        'ɡ' => 'g',
        'һ' => 'h',
        'Н' | 'Η' => 'H',
        'і' | 'ι' | 'ı' | 'ӏ' => 'i',
        'І' | 'Ι' | 'Ӏ' => 'I',
        'ј' => 'j',
        'Ј' => 'J',
        'κ' | 'к' => 'k',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'ո' | 'η' => 'n',
        'Ν' => 'N',
        'о' | 'ο' | 'σ' | 'ӧ' => 'o',
        'О' | 'Ο' => 'O',
        'р' | 'ρ' => 'p',
        'Р' | 'Ρ' => 'P',
        'ԛ' => 'q',
        'г' => 'r',
        'ѕ' => 's',
        'Ѕ' => 'S',
        'т' | 'τ' => 't',
        'Т' | 'Τ' => 'T',
        'υ' | 'ս' => 'u',
        'ν' | 'ѵ' => 'v',
        'ԝ' | 'ω' => 'w',
        'х' | 'χ' => 'x',
        'Х' | 'Χ' => 'X',
        'у' | 'γ' => 'y',
        'У' | 'Υ' => 'Y',
        'Ζ' => 'Z',
        _ => c,
    }
}

/// Leet only inside tokens that mix letters with digits/symbols ("1gn0re", "p@ssw0rd").
fn deleet(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, tok) in s.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let letters = tok.chars().filter(|c| c.is_alphabetic()).count();
        let leet = tok
            .chars()
            .filter(|c| matches!(c, '0' | '1' | '3' | '4' | '5' | '7' | '@' | '$' | '!'))
            .count();
        if letters >= 2 && leet >= 1 {
            for c in tok.chars() {
                out.push(match c {
                    '0' => 'o',
                    '1' | '!' => 'i',
                    '3' => 'e',
                    '4' | '@' => 'a',
                    '5' | '$' => 's',
                    '7' => 't',
                    _ => c,
                });
            }
        } else {
            out.push_str(tok);
        }
    }
    out
}

/// "i g n o r e" / "i.g.n.o.r.e" → "ignore" (runs of ≥4 single letters).
fn join_spaced(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        // try to read a run: L sep L sep L sep L ...
        let mut j = i;
        let mut run = String::new();
        while j < chars.len() && chars[j].is_alphabetic() {
            let next = chars.get(j + 1).copied();
            let prev_ok = j == 0 || !chars[j - 1].is_alphabetic();
            if run.is_empty() && !prev_ok {
                break;
            }
            run.push(chars[j]);
            match next {
                Some(sep)
                    if matches!(sep, ' ' | '.' | '-' | '_' | '*')
                        && chars.get(j + 2).is_some_and(|c| c.is_alphabetic())
                        && !chars.get(j + 3).is_some_and(|c| c.is_alphabetic()) =>
                {
                    j += 2
                }
                Some(c) if c.is_alphabetic() => {
                    run.clear();
                    break;
                }
                _ => {
                    j += 1;
                    break;
                }
            }
        }
        if run.chars().count() >= 4 {
            out.push_str(&run);
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn texts_with_keys(v: &Value, path: &str, out: &mut Vec<(String, String, bool)>) {
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone(), false)),
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
                if path.ends_with("properties") {
                    out.push((format!("{p}#key"), k.clone(), true));
                }
                texts_with_keys(x, &p, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                texts_with_keys(x, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn decoded_payloads(text: &str) -> Vec<String> {
    let mut out = vec![];
    let lenient = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let lenient_url = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    for m in B64ISH.find_iter(text) {
        let body = m.as_str();
        for eng in [&lenient, &lenient_url] {
            if let Ok(b) = eng.decode(body) {
                if b.len() >= 8 && b.iter().all(|c| (0x20..=0x7e).contains(c)) {
                    out.push(String::from_utf8_lossy(&b).into_owned());
                    break;
                }
            }
        }
    }
    for m in HEXISH.find_iter(text) {
        if let Ok(b) = hex::decode(m.as_str()) {
            if b.iter().all(|c| (0x20..=0x7e).contains(c)) {
                out.push(String::from_utf8_lossy(&b).into_owned());
            }
        }
    }
    for m in PCT.find_iter(text) {
        let s = m.as_str();
        let bytes: Vec<u8> = (0..s.len() / 3)
            .filter_map(|i| u8::from_str_radix(&s[i * 3 + 1..i * 3 + 3], 16).ok())
            .collect();
        if bytes.iter().all(|c| (0x20..=0x7e).contains(c)) {
            out.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    out
}

fn instruction_like(n: &str) -> bool {
    N_TAGS.is_match(n)
        || N_OVERRIDE.is_match(n)
        || N_SECRETS.is_match(n)
        || COVERT.is_match(n)
        || INJECT.is_match(n)
        || DEPUTY.is_match(n)
}

/// Canonical skeleton of a tool name for typosquat checks: lower-case, homoglyph and leet
/// folded, separators removed.
pub fn name_skeleton(name: &str) -> String {
    let mut s = String::new();
    for c in name.nfkc() {
        let c = homoglyph(c).to_ascii_lowercase();
        let c = match c {
            '0' => 'o',
            '1' | 'l' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            _ => c,
        };
        if c.is_alphanumeric() {
            s.push(c);
        }
    }
    s
}

/// Optimal-string-alignment distance (Damerau–Levenshtein, adjacent transpositions).
pub fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

fn tool_name(tool: &Value) -> String {
    match tool.get("name") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "?".into(),
    }
}

/// Deep rules only (no v1 findings).
pub fn scan_deep(tool: &Value, external: &HashSet<String>) -> Vec<Finding> {
    let name = tool_name(tool);
    let mut found: Vec<Finding> = vec![];
    let mut ts = vec![];
    if let Some(obj) = tool.as_object() {
        let rest: serde_json::Map<String, Value> = obj
            .iter()
            .filter(|(k, _)| *k != "name")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        texts_with_keys(&Value::Object(rest), "", &mut ts);
    }
    for (path, raw, is_key) in &ts {
        let n = normalize(raw);
        let raw_l = raw.to_lowercase();
        if *is_key {
            if instruction_like(&n) || n.split(' ').count() >= 6 || SENSITIVE.is_match(&n) && COVERT.is_match(&n) {
                found.push(Finding::new(
                    "TP013",
                    HIGH,
                    &name,
                    format!("instruction in schema key {path}"),
                ));
            }
            continue;
        }
        let v1_hit = |re: &Regex| re.is_match(&raw_l);
        if (N_TAGS.is_match(&n) && !v1_hit(&N_TAGS))
            || (N_OVERRIDE.is_match(&n) && !v1_hit(&N_OVERRIDE))
            || (N_SECRETS.is_match(&n) && !v1_hit(&N_SECRETS))
        {
            found.push(Finding::new(
                "TP009",
                HIGH,
                &name,
                format!("obfuscated instruction in {path}"),
            ));
        }
        if COVERT.is_match(&n) && (SENSITIVE.is_match(&n) || SEND_VERB.is_match(&n)) {
            found.push(Finding::new(
                "TP010",
                HIGH,
                &name,
                format!("covert-action phrasing in {path}"),
            ));
        }
        if DEPUTY.is_match(&n) {
            found.push(Finding::new(
                "TP011",
                HIGH,
                &name,
                format!("confused-deputy chain in {path}"),
            ));
        }
        if INJECT.is_match(&n) || INJECT.is_match(&raw_l) {
            found.push(Finding::new(
                "TP012",
                HIGH,
                &name,
                format!("prompt-injection marker in {path}"),
            ));
        }
        if decoded_payloads(raw).iter().any(|d| {
            let dn = normalize(d);
            instruction_like(&dn) || (SENSITIVE.is_match(&dn) && SEND_VERB.is_match(&dn))
        }) {
            found.push(Finding::new(
                "TP014",
                HIGH,
                &name,
                format!("encoded instruction in {path}"),
            ));
        }
        if OBF_SINK.is_match(&raw_l) && SEND_VERB.is_match(&n) {
            found.push(Finding::new(
                "TP015",
                MEDIUM,
                &name,
                format!("obfuscated exfil sink in {path}"),
            ));
        }
        if path.contains("properties.") && path.ends_with(".description") && PARAM_ASK.is_match(&n)
        {
            found.push(Finding::new(
                "TP016",
                HIGH,
                &name,
                format!("parameter asks for conversation/secrets in {path}"),
            ));
        }
    }
    // typosquat / collision against tools on other servers
    let sk = name_skeleton(&name);
    let mut ext: Vec<&String> = external.iter().filter(|e| **e != name).collect();
    ext.sort();
    for e in &ext {
        let ek = name_skeleton(e);
        if sk.len() >= 5 && (sk == ek || osa_distance(&sk, &ek) == 1) {
            found.push(Finding::new(
                "SH001",
                HIGH,
                &name,
                format!("name imitates tool '{e}' on another server"),
            ));
        }
    }
    if external.contains(&name) {
        found.push(Finding::new(
            "SH002",
            LOW,
            &name,
            format!("name collides with tool '{name}' on another server"),
        ));
    }
    let mut seen = HashSet::new();
    found.retain(|f| seen.insert((f.rule.clone(), f.detail.clone())));
    found
}

/// Full check of one tool: v1 poisoning + scopes + deep rules, with the TP005 refinement.
///
/// `siblings`: other tools on the same server. `external`: tools on other servers in the session.
pub fn scan_tool(
    tool: &Value,
    siblings: &HashSet<String>,
    external: &HashSet<String>,
    scopes: &[String],
) -> Vec<Finding> {
    let name = tool_name(tool);
    let mut known: HashSet<String> = siblings.union(external).cloned().collect();
    known.insert(name.clone());
    let mut found = scan_poisoning(tool, &known);
    let joined = texts_joined(tool);
    for f in found.iter_mut().filter(|f| f.rule == "TP005") {
        let other = f.detail.split('\'').nth(1).unwrap_or("").to_string();
        if siblings.contains(&other) && !external.contains(&other) && !hooked(&joined, &other) {
            f.severity = LOW.into();
            f.detail.push_str(" [same server, no hook]");
        }
    }
    // v1 TP003 / TP006 refinements: benign handling notes and verb/sink in different sentences.
    let mut ts = vec![];
    if let Some(obj) = tool.as_object() {
        let rest: serde_json::Map<String, Value> =
            obj.iter().filter(|(k, _)| *k != "name").map(|(k, v)| (k.clone(), v.clone())).collect();
        texts_with_keys(&Value::Object(rest), "", &mut ts);
    }
    let by_path: HashMap<String, String> =
        ts.into_iter().filter(|t| !t.2).map(|(p, t, _)| (p, t)).collect();
    for f in found.iter_mut().filter(|f| f.rule == "TP003" || f.rule == "TP006") {
        let path = f.detail.rsplit(" in ").next().unwrap_or("");
        let Some(text) = by_path.get(path) else { continue };
        let sents = sentences(text);
        let benign = if f.rule == "TP003" {
            sents.iter().filter(|s| SECRETS.is_match(s)).all(|s| {
                let n = normalize(s);
                SAFE_HANDLING.is_match(&n) && !instruction_like(&n) && !COVERT.is_match(&n)
            })
        } else {
            !sents.iter().any(|s| URL.is_match(s) && EXFIL_VERB.is_match(s))
        };
        if benign {
            f.severity = LOW.into();
            f.detail.push_str(if f.rule == "TP003" { " [benign handling note]" } else { " [verb and sink in different sentences]" });
        }
    }
    found.extend(scan_scopes(tool, scopes));
    found.extend(scan_deep(tool, external));
    found
}

fn sentences(text: &str) -> Vec<&str> {
    SENT_SPLIT.split(text).filter(|s| !s.trim().is_empty()).collect()
}

fn texts_joined(tool: &Value) -> String {
    let mut ts = vec![];
    if let Some(obj) = tool.as_object() {
        let rest: serde_json::Map<String, Value> = obj
            .iter()
            .filter(|(k, _)| *k != "name")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        texts_with_keys(&Value::Object(rest), "", &mut ts);
    }
    ts.into_iter()
        .filter(|t| !t.2)
        .map(|t| t.1)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Does a sentence that mentions `other` also hook it ("when X is used", "instead of X")?
fn hooked(text: &str, other: &str) -> bool {
    let re = crate::scanner::word_regex(other);
    text.split(['.', '\n', ';']).filter(|s| re.is_match(s)).any(|s| {
        let l = s.to_lowercase();
        HOOK.is_match(s) || l.contains("also call") || l.contains("also send") || l.contains("bcc")
    })
}

/// Scan a whole server in a session. `external`: tool names on other servers.
pub fn scan_server(
    tools: &[Value],
    scopes_by_tool: &BTreeMap<String, Vec<String>>,
    external: &HashSet<String>,
) -> Vec<Finding> {
    let names: HashSet<String> = tools.iter().map(tool_name).collect();
    let mut out = vec![];
    for t in tools {
        let n = tool_name(t);
        let mut sib = names.clone();
        sib.remove(&n);
        let scopes = scopes_by_tool.get(&n).cloned().unwrap_or_default();
        out.extend(scan_tool(t, &sib, external, &scopes));
    }
    out
}

/// Blocking severity: HIGH or MEDIUM.
pub fn flagged(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.severity == HIGH || f.severity == MEDIUM)
}

/// Blocking poisoning finding (everything except the SC* scope advisories).
pub fn poison_flagged(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| (f.severity == HIGH || f.severity == MEDIUM) && !f.rule.starts_with("SC"))
}
