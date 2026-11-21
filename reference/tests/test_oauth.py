import secrets

import pytest
from conftest import REDIRECT, RESOURCE, Client, get_token

from mcpgw.oauth import OAuthError, pkce_challenge, verify_access_token


def test_metadata_advertises_s256_only(auth, gw):
    md = auth.metadata()
    assert md["code_challenge_methods_supported"] == ["S256"]
    prm = gw.well_known()
    assert prm["resource"] == RESOURCE and prm["authorization_servers"] == [
        "https://auth.example"
    ]


def test_pkce_plain_and_missing_rejected(auth):
    for method, chal in (("plain", "abc"), (None, None)):
        with pytest.raises(OAuthError):
            auth.authorize(
                client_id="cli",
                redirect_uri=REDIRECT,
                scope="mcp:read",
                code_challenge=chal,
                code_challenge_method=method,
                resource=RESOURCE,
            )


def test_wrong_verifier_and_redirect_mismatch(auth):
    v = secrets.token_urlsafe(40)
    with pytest.raises(OAuthError, match="redirect_uri"):
        auth.authorize(
            client_id="cli",
            redirect_uri="https://evil.example/cb",
            scope="mcp:read",
            code_challenge=pkce_challenge(v),
            code_challenge_method="S256",
            resource=RESOURCE,
        )
    code = auth.authorize(
        client_id="cli",
        redirect_uri=REDIRECT,
        scope="mcp:read",
        code_challenge=pkce_challenge(v),
        code_challenge_method="S256",
        resource=RESOURCE,
    )
    with pytest.raises(OAuthError, match="PKCE"):
        auth.token(
            grant_type="authorization_code",
            client_id="cli",
            code=code,
            code_verifier="wrong",
            redirect_uri=REDIRECT,
            resource=RESOURCE,
        )


def test_code_replay_revokes_first_token(auth, gw):
    v = secrets.token_urlsafe(40)
    code = auth.authorize(
        client_id="cli",
        redirect_uri=REDIRECT,
        scope="mcp:read",
        code_challenge=pkce_challenge(v),
        code_challenge_method="S256",
        resource=RESOURCE,
    )
    kw = dict(
        grant_type="authorization_code",
        client_id="cli",
        code=code,
        code_verifier=v,
        redirect_uri=REDIRECT,
        resource=RESOURCE,
    )
    tok = auth.token(**kw)["access_token"]
    with pytest.raises(OAuthError, match="already used"):
        auth.token(**kw)
    st, _, body = gw.handle_http(
        {"Authorization": f"Bearer {tok}"},
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert st == 401 and body["error_description"] == "revoked"


def test_token_for_other_resource_rejected(auth, gw):
    tok = get_token(auth, resource="https://other-mcp.example/mcp")["access_token"]
    st, h, body = gw.handle_http(
        {"Authorization": f"Bearer {tok}"},
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert st == 401 and "audience" in body["error_description"]
    assert "resource_metadata=" in h["WWW-Authenticate"]


def test_expired_and_tampered_tokens(auth, gw, clock):
    tok = get_token(auth)["access_token"]
    head, payload, sig = tok.split(".")
    bad = f"{head}.{payload}.{sig[:-2]}AA"
    st, _, body = gw.handle_http(
        {"Authorization": f"Bearer {bad}"},
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
    )
    assert st == 401 and body["error_description"] == "bad signature"
    clock.t += 301
    with pytest.raises(OAuthError, match="expired"):
        verify_access_token(
            tok, key=auth.key, issuer=auth.issuer, audience=RESOURCE, clock=clock
        )


def test_refresh_rotation_and_reuse_detection(auth):
    t1 = get_token(auth)
    t2 = auth.token(
        grant_type="refresh_token", client_id="cli", refresh_token=t1["refresh_token"]
    )
    with pytest.raises(OAuthError, match="reuse"):
        auth.token(
            grant_type="refresh_token",
            client_id="cli",
            refresh_token=t1["refresh_token"],
        )
    with pytest.raises(OAuthError, match="revoked"):  # whole family is now dead
        auth.token(
            grant_type="refresh_token",
            client_id="cli",
            refresh_token=t2["refresh_token"],
        )


def test_missing_bearer_gets_challenge(gw):
    st, h, _ = gw.handle_http({}, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert st == 401 and h["WWW-Authenticate"].startswith("Bearer resource_metadata=")


def test_insufficient_scope_returns_403(auth, gw, servers_mod):
    gw.connect("weather", servers_mod.weather())
    gw.approve("weather")
    c = Client(gw, get_token(auth, scope="mcp:read")["access_token"])
    st, h, body = c.rpc(
        "tools/call",
        {"name": "weather__get_forecast", "arguments": {"city": "Chicago"}},
    )
    assert st == 403 and 'scope="weather:read"' in h["WWW-Authenticate"]
    assert gw.servers["weather"].upstream.calls() == []
