"""MCP protocol version negotiation and spec-migration shims.

Revisions handled (date-stamped MCP spec versions):
- 2024-11-05: base protocol; no tool annotations, no structured tool output.
- 2025-03-26: adds tool annotations and JSON-RPC batching.
- 2025-06-18: removes JSON-RPC batching; adds structuredContent/outputSchema and tool `title`;
              HTTP clients must send the MCP-Protocol-Version header.
- 2025-11-25: latest revision this gateway knows; treated like 2025-06-18 for the shims below.

The gateway negotiates a version with each client and, separately, with each upstream server,
then rewrites messages so either side sees the shape its version expects.
"""

from __future__ import annotations

import json

import jsonschema

SUPPORTED = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
LATEST = SUPPORTED[-1]
HEADER_DEFAULT = "2025-03-26"  # spec: assume this when the header is absent


def negotiate(requested: str | None) -> str:
    """Spec rule: echo the client's version if supported, otherwise offer our latest."""
    return requested if requested in SUPPORTED else LATEST


def supports_batching(v: str) -> bool:
    return v == "2025-03-26"


def has_annotations(v: str) -> bool:
    return v >= "2025-03-26"


def has_structured_output(v: str) -> bool:
    return v >= "2025-06-18"


def requires_version_header(v: str) -> bool:
    return v >= "2025-06-18"


def adapt_tool_def(tool: dict, client_v: str) -> dict:
    """Strip fields the client's version does not define."""
    t = dict(tool)
    if not has_annotations(client_v):
        t.pop("annotations", None)
    if not has_structured_output(client_v):
        t.pop("outputSchema", None)
        t.pop("title", None)
    return t


def adapt_tool_result(
    result: dict, upstream_v: str, client_v: str, output_schema: dict | None
) -> dict:
    r = json.loads(json.dumps(result))
    if (
        has_structured_output(client_v)
        and not has_structured_output(upstream_v)
        and output_schema
    ):
        # Upgrade shim: old upstream returns JSON as text; lift it into structuredContent.
        if "structuredContent" not in r:
            for block in r.get("content", []):
                if block.get("type") == "text":
                    try:
                        data = json.loads(block["text"])
                        jsonschema.validate(data, output_schema)
                        r["structuredContent"] = data
                    except (ValueError, jsonschema.ValidationError):
                        pass
                    break
    if not has_structured_output(client_v) and "structuredContent" in r:
        # Downgrade shim: keep the data reachable as a text block.
        data = r.pop("structuredContent")
        if not any(b.get("type") == "text" for b in r.get("content", [])):
            r.setdefault("content", []).append(
                {"type": "text", "text": json.dumps(data)}
            )
    return r
