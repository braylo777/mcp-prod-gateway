"""Write tests/fixtures/parity_core.json: Python reference outputs for canon JSON, PKCE, HS256
JWT signing, version negotiation and both version shims. `--check` exits 1 if stale.

The key below is a fixed test value, not a secret.
"""
import json
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from mcpgw import versions  # noqa: E402
from mcpgw.oauth import pkce_challenge, sign_jwt  # noqa: E402

KEY = b"parity-fixture-key-not-a-secret"
V = versions.SUPPORTED


def tools(n):
    lines = (ROOT / "corpus" / "attacks.jsonl").read_text().splitlines()
    return [json.loads(x)["tool"] for x in lines[::max(1, len(lines) // n)]][:n]


def main():
    vals = tools(120) + [
        None, True, False, 0, -7, 3, 21.5, 0.1, 1e-7, 2.5e10, 1e300, "é😀 \x00", [], {},
        {"b": 1, "a": [1, {"d": None, "c": "x"}]}, "<script>\"quoted\"</script>",
    ]
    canon = [[v, json.dumps(v, sort_keys=True, separators=(",", ":")), json.dumps(v)] for v in vals]
    pkce = [[s, pkce_challenge(s)] for s in ["a", "x" * 43, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "ünïcode-verifier", "0" * 128]]
    claims = [
        {"iss": "https://auth.example", "aud": "https://gw.example/mcp", "sub": "cli", "scope": "mcp:read", "exp": 1700000600, "iat": 1700000000, "jti": "j1"},
        {"aud": ["a", "b"], "x": "ü", "n": 1.5, "nested": {"z": 1, "a": 2}},
        {},
    ]
    jwt = [[c, sign_jwt(c, KEY)] for c in claims]
    negotiate = [[r, versions.negotiate(r)] for r in [None, "", "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2099-01-01", "garbage"]]
    adapt_def = []
    for t in tools(40):
        t = dict(t, annotations={"readOnlyHint": True}, title="T", outputSchema={"type": "object"})
        for v in V:
            adapt_def.append([t, v, versions.adapt_tool_def(t, v)])
    schema = {"type": "object", "properties": {"sum": {"type": "number"}}, "required": ["sum"]}
    results = [
        {"content": [{"type": "text", "text": '{"sum": 3}'}]},
        {"content": [{"type": "text", "text": '{"total": 3}'}]},
        {"content": [{"type": "text", "text": "not json"}]},
        {"content": [{"type": "text", "text": '{"sum": "three"}'}]},
        {"content": [{"type": "image", "data": "x"}, {"type": "text", "text": '{"sum": 1.5}'}]},
        {"content": [], "structuredContent": {"sum": 9}},
        {"structuredContent": {"temp_c": 21.5}},
        {"content": [{"type": "text", "text": "21.5"}], "structuredContent": {"temp_c": 21.5}},
        {"isError": True, "content": [{"type": "text", "text": "boom"}]},
    ]
    adapt_res = []
    for r in results:
        for up in V:
            for cl in V:
                for sch in (schema, None):
                    adapt_res.append([r, up, cl, sch, versions.adapt_tool_result(r, up, cl, sch)])
    vcases = []
    for data in [{"sum": 1}, {"sum": "x"}, {}, [], {"sum": 1, "extra": True}, {"sum": None}, {"sum": 2.5}]:
        vcases.append([data, schema, jsonschema.Draft202012Validator(schema).is_valid(data)])
    arr = {"type": "array", "items": {"type": "integer"}}
    for data in [[1, 2], [1, "a"], [], {"a": 1}, [1.5]]:
        vcases.append([data, arr, jsonschema.Draft202012Validator(arr).is_valid(data)])
    out = {"generated_by": "python reference", "canon": canon, "pkce": pkce, "jwt_key": KEY.decode(), "jwt": jwt,
           "negotiate": negotiate, "adapt_tool_def": adapt_def, "adapt_tool_result": adapt_res, "validate": vcases}
    text = json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n"
    path = ROOT / "tests" / "fixtures" / "parity_core.json"
    if "--check" in sys.argv:
        sys.exit(0 if path.exists() and path.read_text() == text else 1)
    path.write_text(text)
    n = sum(len(out[k]) for k in ("canon", "pkce", "jwt", "negotiate", "adapt_tool_def", "adapt_tool_result", "validate"))
    print(f"{n} core parity cases -> {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
