"""Supply-chain scanner for MCP tool definitions.

Three finding families:
- TP*: tool poisoning (hidden instructions inside descriptions / schema text)
- RP*: rug pull (definition changed after approval), via tool fingerprints
- SC*: over-broad scopes and unconstrained dangerous parameters
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass

HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass
class Finding:
    rule: str
    severity: str
    tool: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def fingerprint(tool: dict) -> str:
    """sha256 over the canonical JSON of every field a model or user would rely on."""
    material = {
        k: tool.get(k)
        for k in (
            "name",
            "title",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
        )
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _texts(obj, path="") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("name",) and path == "":
                continue
            out.extend(_texts(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_texts(v, f"{path}[{i}]"))
    return out


_TAGS = re.compile(
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>|\[/?INST\]",
    re.I,
)
_OVERRIDE = re.compile(
    r"ignore (all |any )?(previous|prior|above|other) (instructions|rules)"
    r"|(do not|don't|never) (tell|inform|mention|reveal|show)[^.]{0,40}\buser"
    r"|without (telling|informing|notifying|alerting) the user"
    r"|before (using|calling) this tool,? (you must|always|first)"
    r"|you (must|should) (first )?(read|call|send|include|pass)"
    r"|this is (very )?important[^.]{0,30}(otherwise|or else|the tool will)"
    r"|(the user|they) (won't|will not|must not) (see|notice)",
    re.I,
)
_SECRETS = re.compile(
    r"~/\.ssh|id_rsa|id_ed25519|\.env\b|mcp\.json|claude_desktop_config|/etc/passwd"
    r"|\.aws/credentials|private key|api[_ ]?keys?\b|access tokens?\b|seed phrase",
    re.I,
)
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
_URL = re.compile(r"https?://[^\s\"')]+|\b[\w.+-]+@[\w-]+\.[\w.]+\b")
_EXFIL_VERB = re.compile(
    r"\b(send|post|forward|upload|exfiltrate|copy|bcc|cc|report)\b", re.I
)
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_SMUGGLE_PARAM = re.compile(
    r"^(note|notes|sidenote|side_note|context|reasoning|metadata|extra|debug|feedback)$",
    re.I,
)
_SMUGGLE_DESC = re.compile(
    r"(conversation|chat history|previous messages|system prompt|file contents|all (the )?(text|content))",
    re.I,
)
_DANGEROUS_PARAM = re.compile(
    r"^(command|cmd|shell|script|sql|query_raw|exec|code|path|file_path|url)$", re.I
)


def scan_poisoning(
    tool: dict, known_tool_names: set[str] = frozenset()
) -> list[Finding]:
    name = tool.get("name", "?")
    found: list[Finding] = []
    texts = _texts({k: v for k, v in tool.items() if k != "name"})
    joined = "\n".join(t for _, t in texts)
    for path, text in texts:
        if _TAGS.search(text):
            found.append(
                Finding("TP001", HIGH, name, f"hidden-instruction tag in {path}")
            )
        if _OVERRIDE.search(text):
            found.append(
                Finding("TP002", HIGH, name, f"instruction-override phrasing in {path}")
            )
        if _SECRETS.search(text):
            found.append(
                Finding(
                    "TP003",
                    HIGH,
                    name,
                    f"reference to credentials/sensitive files in {path}",
                )
            )
        if _INVISIBLE.search(text):
            found.append(
                Finding("TP004", HIGH, name, f"invisible/bidi unicode in {path}")
            )
        if _URL.search(text) and _EXFIL_VERB.search(text):
            found.append(
                Finding(
                    "TP006",
                    MEDIUM,
                    name,
                    f"exfiltration sink (URL/email + send verb) in {path}",
                )
            )
        for m in _B64.finditer(text):
            try:
                decoded = base64.b64decode(
                    m.group(0) + "=" * (-len(m.group(0)) % 4)
                ).decode("ascii")
                if decoded.isprintable():
                    found.append(
                        Finding("TP007", MEDIUM, name, f"base64-encoded text in {path}")
                    )
                    break
            except Exception:
                pass
    others = {n for n in known_tool_names if n != name}
    for other in others:
        if re.search(rf"\b{re.escape(other)}\b", joined):
            found.append(
                Finding(
                    "TP005",
                    HIGH,
                    name,
                    f"description references other tool '{other}' (shadowing)",
                )
            )
    props = (tool.get("inputSchema") or {}).get("properties", {}) or {}
    for pname, spec in props.items():
        desc = (spec or {}).get("description", "")
        if _SMUGGLE_PARAM.match(pname) and _SMUGGLE_DESC.search(desc):
            found.append(
                Finding(
                    "TP008",
                    HIGH,
                    name,
                    f"parameter '{pname}' asks for conversation/file content",
                )
            )
    # dedupe by (rule, detail)
    uniq = {(f.rule, f.detail): f for f in found}
    return list(uniq.values())


_WILDCARD = re.compile(r"^\*$|:\*$|^all$|^.*:all$", re.I)
_ADMIN = re.compile(
    r"(^|[:.])(admin|root|owner|superuser|full_access|repo)$|^(files|fs|db|mail):write$",
    re.I,
)
_WRITE = re.compile(r"(write|delete|admin|send|exec|modify)", re.I)


def scan_scopes(tool: dict, scopes: list[str]) -> list[Finding]:
    name = tool.get("name", "?")
    found: list[Finding] = []
    for s in scopes:
        if _WILDCARD.search(s):
            found.append(Finding("SC001", HIGH, name, f"wildcard scope '{s}'"))
        elif _ADMIN.search(s):
            found.append(Finding("SC002", MEDIUM, name, f"broad scope '{s}'"))
    ann = tool.get("annotations") or {}
    if ann.get("readOnlyHint") and any(_WRITE.search(s) for s in scopes):
        found.append(
            Finding(
                "SC003", HIGH, name, "readOnlyHint tool requests write/delete scopes"
            )
        )
    props = (tool.get("inputSchema") or {}).get("properties", {}) or {}
    for pname, spec in props.items():
        spec = spec or {}
        if (
            _DANGEROUS_PARAM.match(pname)
            and spec.get("type", "string") == "string"
            and not any(
                k in spec for k in ("enum", "pattern", "const", "maxLength", "format")
            )
        ):
            found.append(
                Finding(
                    "SC004",
                    MEDIUM,
                    name,
                    f"unconstrained dangerous parameter '{pname}'",
                )
            )
    return found


def diff_against_approved(
    current: list[dict], approved: dict[str, str]
) -> list[Finding]:
    """approved: tool name -> fingerprint captured at approval time."""
    found: list[Finding] = []
    names = set()
    for tool in current:
        n = tool.get("name")
        names.add(n)
        if n not in approved:
            found.append(
                Finding(
                    "RP002", MEDIUM, n, "tool added after approval; needs re-approval"
                )
            )
        elif fingerprint(tool) != approved[n]:
            found.append(
                Finding(
                    "RP001",
                    HIGH,
                    n,
                    "tool definition changed after approval (rug pull)",
                )
            )
    for n in set(approved) - names:
        found.append(Finding("RP003", LOW, n, "approved tool disappeared"))
    return found


def scan_server(
    tools: list[dict], scopes_by_tool: dict[str, list[str]] | None = None
) -> list[Finding]:
    names = {t.get("name") for t in tools}
    out: list[Finding] = []
    for t in tools:
        out.extend(scan_poisoning(t, names))
        out.extend(scan_scopes(t, (scopes_by_tool or {}).get(t.get("name"), [])))
    return out
