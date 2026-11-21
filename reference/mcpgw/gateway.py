"""The gateway: OAuth-protected MCP front door with allowlist, scanning and version shims."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from . import versions
from .oauth import (
    AuthorizationServer,
    OAuthError,
    protected_resource_metadata,
    verify_access_token,
)
from .scanner import HIGH, Finding, diff_against_approved, fingerprint, scan_server

SEP = "__"


class Upstream(Protocol):
    url: str

    def handle(self, msg: dict, headers: dict) -> dict: ...


@dataclass
class AllowEntry:
    server_id: str
    url: str
    tool_scopes: dict[str, list[str]] = field(
        default_factory=dict
    )  # scopes a client needs per tool
    output_schemas: dict[str, dict] = field(
        default_factory=dict
    )  # for upgrade shims on old upstreams


class Allowlist:
    def __init__(self, entries: list[AllowEntry]):
        self.entries = {e.server_id: e for e in entries}

    def check(self, server_id: str, url: str) -> AllowEntry:
        e = self.entries.get(server_id)
        if e is None:
            raise PermissionError(f"server '{server_id}' is not on the allowlist")
        if e.url != url:
            raise PermissionError(
                f"server '{server_id}' url {url} does not match pinned {e.url}"
            )
        if not (
            url.startswith("https://")
            or url.startswith("http://127.0.0.1")
            or url.startswith("http://localhost")
        ):
            raise PermissionError("remote servers must use https")
        return e


@dataclass
class _Server:
    entry: AllowEntry
    upstream: Upstream
    version: str = ""
    approved: dict[str, str] = field(default_factory=dict)  # tool -> fingerprint
    tools: dict[str, dict] = field(default_factory=dict)  # last seen definitions
    quarantined: set[str] = field(default_factory=set)
    status: str = "connected"  # connected | approved | rejected


def _rpc_error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _rpc_ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


class Gateway:
    def __init__(
        self,
        resource: str,
        auth: AuthorizationServer,
        allowlist: Allowlist,
        clock: Callable[[], float] = time.time,
    ):
        self.resource = resource
        self.auth = auth
        self.allowlist = allowlist
        self.clock = clock
        self.servers: dict[str, _Server] = {}
        self.sessions: dict[str, str] = {}  # session id -> negotiated client version
        self.audit: list[dict] = []

    def _log(self, event: str, **kw):
        self.audit.append({"event": event, **kw})

    # --- upstream management -------------------------------------------
    def connect(self, server_id: str, upstream: Upstream) -> None:
        entry = self.allowlist.check(server_id, upstream.url)
        resp = upstream.handle(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": versions.LATEST,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-prod-gateway", "version": "0.1"},
                },
            },
            self._upstream_headers(server_id, None),
        )
        v = resp["result"]["protocolVersion"]
        if v not in versions.SUPPORTED:
            raise ConnectionError(f"upstream speaks unsupported version {v}")
        self.servers[server_id] = _Server(entry, upstream, version=v)
        self._log("connect", server=server_id, version=v)

    def _upstream_headers(self, server_id: str, version: str | None) -> dict:
        # The client's token is never forwarded (no token passthrough). The gateway uses its own
        # per-upstream credential; here a non-secret placeholder reference.
        h = {"Authorization": f"Bearer <upstream-credential:{server_id}>"}
        if version and versions.requires_version_header(version):
            h["MCP-Protocol-Version"] = version
        return h

    def _fetch_tools(self, sid: str) -> list[dict]:
        s = self.servers[sid]
        resp = s.upstream.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            self._upstream_headers(sid, s.version),
        )
        tools = resp["result"]["tools"]
        s.tools = {t["name"]: t for t in tools}
        return tools

    def approve(self, server_id: str) -> list[Finding]:
        s = self.servers[server_id]
        tools = self._fetch_tools(server_id)
        findings = scan_server(tools, s.entry.tool_scopes)
        if any(f.severity == HIGH for f in findings):
            s.status = "rejected"
            self._log(
                "approval_rejected",
                server=server_id,
                findings=[f.to_dict() for f in findings],
            )
            return findings
        s.approved = {t["name"]: fingerprint(t) for t in tools}
        s.status = "approved"
        self._log("approved", server=server_id, tools=sorted(s.approved))
        return findings

    def recheck(self, server_id: str) -> list[Finding]:
        """Re-fetch definitions and quarantine anything that drifted from the approved snapshot."""
        s = self.servers[server_id]
        tools = self._fetch_tools(server_id)
        drift = diff_against_approved(tools, s.approved)
        fresh = scan_server(tools, s.entry.tool_scopes)
        for f in drift + fresh:
            if f.rule in ("RP001", "RP002") or f.severity == HIGH:
                if f.tool not in s.quarantined:
                    s.quarantined.add(f.tool)
                    self._log("quarantine", server=server_id, tool=f.tool, rule=f.rule)
        return drift + fresh

    # --- client-facing HTTP surface -------------------------------------
    def well_known(self) -> dict:
        scopes = sorted(
            {
                sc
                for s in self.allowlist.entries.values()
                for v in s.tool_scopes.values()
                for sc in v
            }
        )
        return protected_resource_metadata(self.resource, [self.auth.issuer], scopes)

    def handle_http(self, headers: dict, body) -> tuple[int, dict, object]:
        h = {k.lower(): v for k, v in headers.items()}
        challenge = {
            "WWW-Authenticate": f'Bearer resource_metadata="{self.resource}/.well-known/oauth-protected-resource"'
        }
        authz = h.get("authorization", "")
        if not authz.startswith("Bearer "):
            return 401, challenge, {"error": "unauthorized"}
        try:
            claims = verify_access_token(
                authz[7:],
                key=self.auth.key,
                issuer=self.auth.issuer,
                audience=self.resource,
                clock=self.clock,
                revocation=self.auth.is_revoked,
            )
        except OAuthError as e:
            self._log("auth_failed", reason=e.description)
            return (
                401,
                challenge,
                {"error": e.error, "error_description": e.description},
            )
        granted = set(claims.get("scope", "").split())

        if isinstance(body, list):
            sid = h.get("mcp-session-id")
            v = self.sessions.get(sid or "")
            if v is None:
                return (
                    400,
                    {},
                    _rpc_error(None, -32600, "batch requires an initialized session"),
                )
            if not versions.supports_batching(v):
                return (
                    400,
                    {},
                    _rpc_error(None, -32600, f"JSON-RPC batching not allowed in {v}"),
                )
            if any(m.get("method") == "initialize" for m in body):
                return (
                    400,
                    {},
                    _rpc_error(None, -32600, "initialize must not be batched"),
                )
            return 200, {}, [self._dispatch(m, v, granted) for m in body]

        if body.get("method") == "initialize":
            v = versions.negotiate(body.get("params", {}).get("protocolVersion"))
            sid = secrets.token_hex(12)
            self.sessions[sid] = v
            self._log(
                "session",
                version=v,
                requested=body.get("params", {}).get("protocolVersion"),
            )
            return (
                200,
                {"Mcp-Session-Id": sid},
                _rpc_ok(
                    body.get("id"),
                    {
                        "protocolVersion": v,
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": "mcp-prod-gateway", "version": "0.1"},
                    },
                ),
            )

        sid = h.get("mcp-session-id")
        if not sid:
            return 400, {}, _rpc_error(body.get("id"), -32600, "missing Mcp-Session-Id")
        v = self.sessions.get(sid)
        if v is None:
            return 404, {}, _rpc_error(body.get("id"), -32600, "unknown session")
        hv = h.get("mcp-protocol-version")
        if hv is not None and (hv not in versions.SUPPORTED or hv != v):
            return (
                400,
                {},
                _rpc_error(
                    body.get("id"),
                    -32600,
                    f"MCP-Protocol-Version {hv} != negotiated {v}",
                ),
            )
        resp = self._dispatch(body, v, granted)
        if "error" in resp and resp["error"]["code"] == -32003:
            return (
                403,
                {
                    "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{resp["error"].get("data", "")}"'
                },
                resp,
            )
        return 200, {}, resp

    def _dispatch(self, msg: dict, client_v: str, granted: set[str]) -> dict:
        mid, method = msg.get("id"), msg.get("method")
        if method == "tools/list":
            out = []
            for sid, s in self.servers.items():
                if s.status != "approved":
                    continue
                self.recheck(sid)
                for name, t in s.tools.items():
                    if name in s.quarantined or name not in s.approved:
                        continue
                    t2 = dict(t, name=f"{sid}{SEP}{name}")
                    if name in s.entry.output_schemas and "outputSchema" not in t2:
                        t2["outputSchema"] = s.entry.output_schemas[name]
                    out.append(versions.adapt_tool_def(t2, client_v))
            return _rpc_ok(mid, {"tools": out})
        if method == "tools/call":
            params = msg.get("params", {})
            full = params.get("name", "")
            sid, _, tname = full.partition(SEP)
            s = self.servers.get(sid)
            if s is None or s.status != "approved":
                self._log("blocked", tool=full, reason="server not approved")
                return _rpc_error(mid, -32602, f"unknown or unapproved server '{sid}'")
            self.recheck(sid)
            if tname in s.quarantined or tname not in s.approved:
                self._log("blocked", tool=full, reason="quarantined or unapproved tool")
                return _rpc_error(
                    mid, -32602, f"tool '{full}' is quarantined or not approved"
                )
            need = set(s.entry.tool_scopes.get(tname, []))
            if not need <= granted:
                self._log("blocked", tool=full, reason="insufficient_scope")
                err = _rpc_error(mid, -32003, "insufficient_scope")
                err["error"]["data"] = " ".join(sorted(need))
                return err
            resp = s.upstream.handle(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "method": "tools/call",
                    "params": {"name": tname, "arguments": params.get("arguments", {})},
                },
                self._upstream_headers(sid, s.version),
            )
            if "result" in resp:
                schema = s.tools[tname].get(
                    "outputSchema"
                ) or s.entry.output_schemas.get(tname)
                resp["result"] = versions.adapt_tool_result(
                    resp["result"], s.version, client_v, schema
                )
            self._log("call", tool=full)
            return resp
        if method == "ping":
            return _rpc_ok(mid, {})
        return _rpc_error(mid, -32601, f"method not found: {method}")


def dumps(o) -> str:
    return json.dumps(o, sort_keys=True)
