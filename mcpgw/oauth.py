"""Minimal OAuth 2.1 authorization server + resource-server token checks for remote MCP.

Implements the parts the MCP authorization spec leans on:
- Authorization-code grant with mandatory PKCE (S256 only; "plain" is rejected).
- Exact redirect-URI matching.
- Resource indicators (RFC 8707): tokens are audience-bound to one MCP resource.
- Single-use authorization codes; code replay revokes tokens issued from that code.
- Rotating refresh tokens; reuse of a rotated refresh token revokes the whole family.
- Authorization-server metadata (RFC 8414) and protected-resource metadata (RFC 9728).

Access tokens are compact HS256 JWTs signed with the stdlib (no external JWT library).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


class OAuthError(Exception):
    def __init__(self, error: str, description: str = ""):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description


@dataclass
class Client:
    client_id: str
    redirect_uris: list[str]
    allowed_scopes: set[str]


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    scope: str
    challenge: str
    resource: str
    expires_at: float
    used: bool = False
    issued_jtis: list[str] = field(default_factory=list)


def sign_jwt(claims: dict, key: bytes) -> str:
    header = b64url(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    payload = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(sig)}"


def decode_jwt(token: str, key: bytes) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
    except Exception as exc:  # malformed
        raise OAuthError("invalid_token", "malformed token") from exc
    if header.get("alg") != "HS256":
        raise OAuthError("invalid_token", "unexpected alg")
    expected = hmac.new(
        key, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, b64url_decode(sig_b64)):
        raise OAuthError("invalid_token", "bad signature")
    return json.loads(b64url_decode(payload_b64))


class AuthorizationServer:
    def __init__(
        self,
        issuer: str,
        signing_key: bytes,
        token_ttl: int = 300,
        code_ttl: int = 60,
        clock: Callable[[], float] = time.time,
    ):
        self.issuer = issuer
        self.key = signing_key
        self.token_ttl = token_ttl
        self.code_ttl = code_ttl
        self.clock = clock
        self.clients: dict[str, Client] = {}
        self.codes: dict[str, _Code] = {}
        self.refresh: dict[str, dict] = (
            {}
        )  # token -> {family, client_id, scope, resource, active}
        self.revoked_jtis: set[str] = set()
        self.revoked_families: set[str] = set()

    # --- metadata -------------------------------------------------------
    def metadata(self) -> dict:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "registration_endpoint": f"{self.issuer}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    def register_client(
        self, client_id: str, redirect_uris: list[str], allowed_scopes: set[str]
    ) -> Client:
        for uri in redirect_uris:
            if not (
                uri.startswith("https://")
                or uri.startswith("http://127.0.0.1")
                or uri.startswith("http://localhost")
            ):
                raise OAuthError("invalid_redirect_uri", uri)
        c = Client(client_id, list(redirect_uris), set(allowed_scopes))
        self.clients[client_id] = c
        return c

    # --- authorize ------------------------------------------------------
    def authorize(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
        resource: str | None,
    ) -> str:
        client = self.clients.get(client_id)
        if client is None:
            raise OAuthError("unauthorized_client", "unknown client")
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", "redirect_uri mismatch")
        if not code_challenge:
            raise OAuthError("invalid_request", "PKCE code_challenge required")
        if code_challenge_method != "S256":
            raise OAuthError("invalid_request", "only S256 PKCE is allowed")
        if not resource:
            raise OAuthError("invalid_target", "resource indicator required")
        scopes = set(scope.split())
        if not scopes <= client.allowed_scopes:
            raise OAuthError(
                "invalid_scope",
                f"not allowed: {sorted(scopes - client.allowed_scopes)}",
            )
        code = secrets.token_urlsafe(24)
        self.codes[code] = _Code(
            client_id,
            redirect_uri,
            scope,
            code_challenge,
            resource,
            self.clock() + self.code_ttl,
        )
        return code

    # --- token ----------------------------------------------------------
    def _issue(self, client_id: str, scope: str, resource: str, family: str) -> dict:
        now = int(self.clock())
        jti = secrets.token_hex(8)
        access = sign_jwt(
            {
                "iss": self.issuer,
                "aud": resource,
                "sub": client_id,
                "scope": scope,
                "iat": now,
                "exp": now + self.token_ttl,
                "jti": jti,
                "fam": family,
            },
            self.key,
        )
        rt = secrets.token_urlsafe(24)
        self.refresh[rt] = {
            "family": family,
            "client_id": client_id,
            "scope": scope,
            "resource": resource,
            "active": True,
        }
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.token_ttl,
            "refresh_token": rt,
            "scope": scope,
            "_jti": jti,
        }

    def token(
        self,
        *,
        grant_type: str,
        client_id: str,
        code: str | None = None,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
        resource: str | None = None,
        refresh_token: str | None = None,
    ) -> dict:
        if grant_type == "authorization_code":
            rec = self.codes.get(code or "")
            if rec is None:
                raise OAuthError("invalid_grant", "unknown code")
            if rec.used:
                # replay: revoke everything minted from this code
                self.revoked_jtis.update(rec.issued_jtis)
                raise OAuthError("invalid_grant", "code already used")
            if self.clock() > rec.expires_at:
                raise OAuthError("invalid_grant", "code expired")
            if rec.client_id != client_id or rec.redirect_uri != redirect_uri:
                raise OAuthError("invalid_grant", "client or redirect mismatch")
            if not code_verifier or pkce_challenge(code_verifier) != rec.challenge:
                raise OAuthError("invalid_grant", "PKCE verification failed")
            if resource != rec.resource:
                raise OAuthError("invalid_target", "resource mismatch")
            rec.used = True
            out = self._issue(
                client_id, rec.scope, rec.resource, family=secrets.token_hex(6)
            )
            rec.issued_jtis.append(out["_jti"])
            return out
        if grant_type == "refresh_token":
            rec = self.refresh.get(refresh_token or "")
            if rec is None or rec["client_id"] != client_id:
                raise OAuthError("invalid_grant", "unknown refresh token")
            if rec["family"] in self.revoked_families:
                raise OAuthError("invalid_grant", "token family revoked")
            if not rec["active"]:
                self.revoked_families.add(rec["family"])
                raise OAuthError(
                    "invalid_grant", "refresh token reuse detected; family revoked"
                )
            rec["active"] = False
            return self._issue(client_id, rec["scope"], rec["resource"], rec["family"])
        raise OAuthError("unsupported_grant_type", grant_type)

    def is_revoked(self, claims: dict) -> bool:
        return (
            claims.get("jti") in self.revoked_jtis
            or claims.get("fam") in self.revoked_families
        )


def verify_access_token(
    token: str,
    *,
    key: bytes,
    issuer: str,
    audience: str,
    required_scopes: set[str] = frozenset(),
    clock: Callable[[], float] = time.time,
    revocation: Callable[[dict], bool] | None = None,
) -> dict:
    claims = decode_jwt(token, key)
    if claims.get("iss") != issuer:
        raise OAuthError("invalid_token", "wrong issuer")
    if claims.get("aud") != audience:
        raise OAuthError("invalid_token", "token audience is not this resource")
    if clock() >= claims.get("exp", 0):
        raise OAuthError("invalid_token", "expired")
    if revocation and revocation(claims):
        raise OAuthError("invalid_token", "revoked")
    granted = set(claims.get("scope", "").split())
    if not set(required_scopes) <= granted:
        raise OAuthError(
            "insufficient_scope", f"missing {sorted(set(required_scopes) - granted)}"
        )
    return claims


def protected_resource_metadata(
    resource: str, authorization_servers: list[str], scopes: list[str]
) -> dict:
    """RFC 9728 document served at /.well-known/oauth-protected-resource."""
    return {
        "resource": resource,
        "authorization_servers": authorization_servers,
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
    }
