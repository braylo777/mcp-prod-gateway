import pytest
from conftest import Client, get_token

from mcpgw import versions
from mcpgw.gateway import Gateway
from mcpgw.http import serve


@pytest.fixture
def token(auth):
    return get_token(auth)["access_token"]


def test_allowlist_blocks_unknown_and_url_swap(gw, servers_mod):
    s = servers_mod.weather()
    s.url = "https://weather-evil.example"
    with pytest.raises(PermissionError, match="does not match pinned"):
        gw.connect("weather", s)
    with pytest.raises(PermissionError, match="not on the allowlist"):
        gw.connect("random", servers_mod.weather())


def test_version_negotiation(gw, token):
    assert Client(gw, token, "2025-03-26").version == "2025-03-26"
    assert Client(gw, token, "1999-01-01").version == versions.LATEST


def test_protocol_header_mismatch_rejected(gw, token):
    c = Client(gw, token, "2025-06-18")
    st, _, body = c.rpc("ping", extra_headers={"MCP-Protocol-Version": "2025-03-26"})
    assert st == 400 and "negotiated" in body["error"]["message"]
    st, _, _ = c.rpc("ping")
    assert st == 200


def test_batching_only_in_2025_03_26(gw, token):
    old = Client(gw, token, "2025-03-26")
    batch = [{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in (1, 2)]
    st, _, body = gw.handle_http(
        {"Authorization": f"Bearer {token}", "Mcp-Session-Id": old.sid}, batch
    )
    assert st == 200 and [r["id"] for r in body] == [1, 2]
    new = Client(gw, token, "2025-06-18")
    st, _, body = gw.handle_http(
        {"Authorization": f"Bearer {token}", "Mcp-Session-Id": new.sid}, batch
    )
    assert st == 400 and "batching" in body["error"]["message"]


def test_upgrade_shim_lifts_legacy_text_to_structured(gw, token, servers_mod):
    gw.connect("calc", servers_mod.legacy_calc())
    assert gw.servers["calc"].version == "2024-11-05"
    gw.approve("calc")
    c = Client(gw, token, "2025-06-18")
    _, _, body = c.rpc(
        "tools/call", {"name": "calc__add", "arguments": {"a": 2, "b": 3}}
    )
    assert body["result"]["structuredContent"] == {"sum": 5}
    # upstream on 2024-11-05 must not receive the 2025-06-18 header
    _, hdrs = gw.servers["calc"].upstream.received[-1]
    assert "MCP-Protocol-Version" not in hdrs


def test_downgrade_shim_strips_new_fields(gw, token, servers_mod):
    gw.connect("weather", servers_mod.weather())
    gw.approve("weather")
    c = Client(gw, token, "2024-11-05")
    _, _, body = c.rpc("tools/list")
    tool = body["result"]["tools"][0]
    assert tool["name"] == "weather__get_forecast"
    assert not {"annotations", "outputSchema", "title"} & set(tool)
    _, _, body = c.rpc(
        "tools/call", {"name": "weather__get_forecast", "arguments": {"city": "x"}}
    )
    assert (
        "structuredContent" not in body["result"]
        and body["result"]["content"][0]["type"] == "text"
    )


def test_poisoned_server_rejected_and_never_called(gw, token, servers_mod):
    s = servers_mod.poisoned_notes()
    gw.connect("notes", s)
    rules = {f.rule for f in gw.approve("notes")}
    assert {"TP001", "TP002", "TP003", "TP008"} <= rules
    c = Client(gw, token)
    _, _, body = c.rpc("tools/list")
    assert body["result"]["tools"] == []
    _, _, body = c.rpc(
        "tools/call", {"name": "notes__add_note", "arguments": {"text": "hi"}}
    )
    assert "error" in body and s.calls() == []


def test_shadowing_detected(gw, servers_mod):
    gw.connect("facts", servers_mod.shadowing())
    findings = gw.approve("facts")
    assert any(f.rule == "TP005" and f.tool == "daily_tip" for f in findings)
    assert gw.servers["facts"].status == "rejected"


def test_rug_pull_quarantines_tool(gw, token, servers_mod):
    s = servers_mod.RugPullServer()
    gw.connect("translate", s)
    assert gw.approve("translate") == []
    c = Client(gw, token)
    _, _, body = c.rpc(
        "tools/call", {"name": "translate__translate", "arguments": {"text": "hola"}}
    )
    assert body["result"]["content"][0]["text"] == "hola"
    s.flip()
    _, _, body = c.rpc(
        "tools/call", {"name": "translate__translate", "arguments": {"text": "secret"}}
    )
    assert "quarantined" in body["error"]["message"]
    assert len(s.calls()) == 1  # second call never reached upstream
    assert any(e["event"] == "quarantine" and e["rule"] == "RP001" for e in gw.audit)


def test_overbroad_scopes_flagged(gw, servers_mod):
    gw.connect("ops", servers_mod.overbroad())
    rules = {f.rule for f in gw.approve("ops")}
    assert {"SC001", "SC003", "SC004"} <= rules


def test_no_token_passthrough(gw, token, servers_mod):
    s = servers_mod.weather()
    gw.connect("weather", s)
    gw.approve("weather")
    Client(gw, token).rpc(
        "tools/call", {"name": "weather__get_forecast", "arguments": {"city": "x"}}
    )
    assert all(token not in str(h) for _, h in s.received)


def test_over_real_http(gw, token, servers_mod):
    import json
    import urllib.request

    gw.connect("weather", servers_mod.weather())
    gw.approve("weather")
    srv = serve(gw)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        prm = json.loads(
            urllib.request.urlopen(
                f"{base}/.well-known/oauth-protected-resource"
            ).read()
        )
        assert prm["resource"] == gw.resource

        def post(body, headers):
            req = urllib.request.Request(
                base,
                json.dumps(body).encode(),
                {"Content-Type": "application/json", **headers},
            )
            r = urllib.request.urlopen(req)
            return dict(r.headers), json.loads(r.read())

        h, init = post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
            {"Authorization": f"Bearer {token}"},
        )
        _, out = post(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "weather__get_forecast",
                    "arguments": {"city": "Chicago"},
                },
            },
            {
                "Authorization": f"Bearer {token}",
                "Mcp-Session-Id": h["Mcp-Session-Id"],
                "MCP-Protocol-Version": "2025-06-18",
            },
        )
        assert out["result"]["structuredContent"] == {"temp_c": 21.5}
    finally:
        srv.shutdown()


def test_gateway_is_constructible_standalone(auth):
    from mcpgw.gateway import Allowlist

    assert Gateway("https://x/mcp", auth, Allowlist([])).servers == {}
