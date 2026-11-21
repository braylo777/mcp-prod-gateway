import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcpgw.gateway import AllowEntry, Allowlist, Gateway  # noqa: E402
from mcpgw.oauth import AuthorizationServer, pkce_challenge  # noqa: E402
from mocks import servers  # noqa: E402

RESOURCE = "https://gw.example/mcp"
REDIRECT = "http://127.0.0.1:8765/callback"


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def auth(clock):
    a = AuthorizationServer(
        "https://auth.example", secrets.token_bytes(32), clock=clock
    )
    a.register_client(
        "cli",
        [REDIRECT],
        {"mcp:read", "weather:read", "calc:use", "translate:use", "ops:run"},
    )
    return a


def get_token(
    auth, scope="mcp:read weather:read calc:use translate:use", resource=RESOURCE
):
    verifier = secrets.token_urlsafe(40)
    code = auth.authorize(
        client_id="cli",
        redirect_uri=REDIRECT,
        scope=scope,
        code_challenge=pkce_challenge(verifier),
        code_challenge_method="S256",
        resource=resource,
    )
    return auth.token(
        grant_type="authorization_code",
        client_id="cli",
        code=code,
        code_verifier=verifier,
        redirect_uri=REDIRECT,
        resource=resource,
    )


ALLOW = [
    AllowEntry(
        "weather", "https://weather.example", {"get_forecast": ["weather:read"]}
    ),
    AllowEntry(
        "calc",
        "https://calc.example",
        {"add": ["calc:use"]},
        output_schemas={
            "add": {
                "type": "object",
                "properties": {"sum": {"type": "number"}},
                "required": ["sum"],
            }
        },
    ),
    AllowEntry("notes", "https://notes.example", {"add_note": ["mcp:read"]}),
    AllowEntry("facts", "https://facts.example", {}),
    AllowEntry(
        "translate", "https://translate.example", {"translate": ["translate:use"]}
    ),
    AllowEntry("ops", "https://ops.example", {"run": ["*", "ops:admin"]}),
]


@pytest.fixture
def gw(auth, clock):
    return Gateway(RESOURCE, auth, Allowlist(ALLOW), clock=clock)


class Client:
    def __init__(self, gw, token, version="2025-06-18"):
        self.gw, self.token = gw, token
        st, h, body = gw.handle_http(
            {"Authorization": f"Bearer {token}"},
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": version},
            },
        )
        assert st == 200
        self.sid = h["Mcp-Session-Id"]
        self.version = body["result"]["protocolVersion"]

    def rpc(self, method, params=None, id_=2, extra_headers=None):
        h = {
            "Authorization": f"Bearer {self.token}",
            "Mcp-Session-Id": self.sid,
            "MCP-Protocol-Version": self.version,
        }
        h.update(extra_headers or {})
        return self.gw.handle_http(
            h, {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
        )


@pytest.fixture
def servers_mod():
    return servers
