//! MCP protocol version negotiation and spec-migration shims (port of `mcpgw/versions.py`).

use serde_json::{json, Value};

use crate::canon;

pub const SUPPORTED: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
pub const LATEST: &str = "2025-11-25";
pub const HEADER_DEFAULT: &str = "2025-03-26";

/// Echo the client's version if supported, otherwise offer our latest.
pub fn negotiate(requested: Option<&str>) -> String {
    match requested {
        Some(v) if SUPPORTED.contains(&v) => v.to_string(),
        _ => LATEST.to_string(),
    }
}

pub fn supports_batching(v: &str) -> bool {
    v == "2025-03-26"
}
pub fn has_annotations(v: &str) -> bool {
    v >= "2025-03-26"
}
pub fn has_structured_output(v: &str) -> bool {
    v >= "2025-06-18"
}
pub fn requires_version_header(v: &str) -> bool {
    v >= "2025-06-18"
}

/// Strip fields the client's version does not define.
pub fn adapt_tool_def(tool: &Value, client_v: &str) -> Value {
    let mut t = tool.clone();
    if let Some(o) = t.as_object_mut() {
        if !has_annotations(client_v) {
            o.shift_remove("annotations");
        }
        if !has_structured_output(client_v) {
            o.shift_remove("outputSchema");
            o.shift_remove("title");
        }
    }
    t
}

/// Minimal JSON Schema check (type, required, properties, items). The Python side uses `jsonschema`;
/// this subset covers every schema the gateway configures.
pub fn validate(data: &Value, schema: &Value) -> bool {
    if let Some(ty) = schema.get("type").and_then(|t| t.as_str()) {
        let ok = match ty {
            "object" => data.is_object(),
            "array" => data.is_array(),
            "string" => data.is_string(),
            "boolean" => data.is_boolean(),
            "null" => data.is_null(),
            "number" => data.is_number(),
            "integer" => {
                data.as_i64().is_some()
                    || data.as_u64().is_some()
                    || data.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false)
            }
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    if let (Some(req), Some(obj)) = (
        schema.get("required").and_then(|r| r.as_array()),
        data.as_object(),
    ) {
        if req
            .iter()
            .filter_map(|r| r.as_str())
            .any(|k| !obj.contains_key(k))
        {
            return false;
        }
    }
    if let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        data.as_object(),
    ) {
        for (k, sub) in props {
            if let Some(v) = obj.get(k) {
                if !validate(v, sub) {
                    return false;
                }
            }
        }
    }
    if let (Some(items), Some(arr)) = (schema.get("items"), data.as_array()) {
        if arr.iter().any(|v| !validate(v, items)) {
            return false;
        }
    }
    true
}

pub fn adapt_tool_result(
    result: &Value,
    upstream_v: &str,
    client_v: &str,
    output_schema: Option<&Value>,
) -> Value {
    let mut r = result.clone();
    let schema = output_schema.filter(|s| s.as_object().map(|o| !o.is_empty()).unwrap_or(false));
    if has_structured_output(client_v) && !has_structured_output(upstream_v) {
        if let Some(schema) = schema {
            // Upgrade shim: old upstream returns JSON as text; lift it into structuredContent.
            if r.get("structuredContent").is_none() {
                let first_text = r
                    .get("content")
                    .and_then(|c| c.as_array())
                    .and_then(|blocks| {
                        blocks
                            .iter()
                            .find(|b| b.get("type") == Some(&json!("text")))
                    })
                    .and_then(|b| b.get("text"))
                    .and_then(|t| t.as_str())
                    .map(str::to_string);
                if let Some(text) = first_text {
                    if let Ok(data) = serde_json::from_str::<Value>(&text) {
                        if validate(&data, schema) {
                            r["structuredContent"] = data;
                        }
                    }
                }
            }
        }
    }
    if !has_structured_output(client_v) {
        if let Some(data) = r
            .as_object_mut()
            .and_then(|o| o.shift_remove("structuredContent"))
        {
            // Downgrade shim: keep the data reachable as a text block.
            let has_text = r
                .get("content")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().any(|b| b.get("type") == Some(&json!("text"))))
                .unwrap_or(false);
            if !has_text {
                let block = json!({"type": "text", "text": canon::dumps(&data, false, false)});
                match r.get_mut("content").and_then(|c| c.as_array_mut()) {
                    Some(a) => a.push(block),
                    None => r["content"] = json!([block]),
                }
            }
        }
    }
    r
}
