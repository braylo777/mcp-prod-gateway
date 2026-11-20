//! Python-compatible JSON serialisation (`json.dumps` with `ensure_ascii=True`).

use serde_json::Value;

/// `json.dumps(v, sort_keys=sort, separators=(",", ":"))` when `compact`, else Python's default `", "` / `": "`.
pub fn dumps(v: &Value, sort_keys: bool, compact: bool) -> String {
    let mut out = String::new();
    write(v, sort_keys, compact, &mut out);
    out
}

fn write(v: &Value, sort: bool, compact: bool, out: &mut String) {
    let (item_sep, kv_sep) = if compact { (",", ":") } else { (", ", ": ") };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => escape(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write(x, sort, compact, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            if sort {
                keys.sort();
            }
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                escape(k, out);
                out.push_str(kv_sep);
                write(&m[*k], sort, compact, out);
            }
            out.push('}');
        }
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e && (c as u32) != 0x7f => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python_ensure_ascii() {
        let v = json!({"b": "é\u{200b}\u{E0049}", "a": [1, 2.5, null, true]});
        let want = concat!(
            "{\"a\":[1,2.5,null,true],\"b\":\"",
            "\\",
            "u00e9",
            "\\",
            "u200b",
            "\\",
            "udb40",
            "\\",
            "udc49\"}"
        );
        assert_eq!(dumps(&v, true, true), want);
        assert_eq!(
            dumps(&json!({"x": 1, "y": [1, 2]}), false, false),
            r#"{"x": 1, "y": [1, 2]}"#
        );
    }
}
