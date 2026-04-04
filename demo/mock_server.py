#!/usr/bin/env python3
"""
Aegis demo — standalone mock MCP server.

Tools exposed:
  echo       — echoes your message back
  add        — adds two numbers
  get_info   — returns server version string
  write_file — pretends to write a file (dangerous tool, good for demo denials)

Protocol: MCP JSON-RPC 2.0 over stdin/stdout, newline-delimited.

Run standalone:
  python3 demo/mock_server.py

Or let aegis-mcp-proxy wrap it:
  aegis-mcp-proxy --policy demo/policy.yaml --agent claude -- python3 demo/mock_server.py
"""

import sys
import json

TOOLS = [
    {
        "name": "echo",
        "description": "Echoes the message argument back to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string", "description": "Text to echo"}},
            "required": ["message"],
        },
    },
    {
        "name": "add",
        "description": "Adds two numbers a and b and returns the sum.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "get_info",
        "description": "Returns information about this mock server.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "write_file",
        "description": "Writes content to a file path on the server.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "Destination file path"},
                "content": {"type": "string", "description": "File content"},
            },
            "required": ["path", "content"],
        },
    },
]


def handle(msg):
    method = msg.get("method", "")
    id_    = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": id_,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "aegis-mock-server", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": id_, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = msg.get("params", {})
        name   = params.get("name", "")
        args   = params.get("arguments", {})

        if   name == "echo":
            text = str(args.get("message", ""))
        elif name == "add":
            text = str(args.get("a", 0) + args.get("b", 0))
        elif name == "get_info":
            text = "aegis-mock-server v1.0.0 — all tool calls pass through Aegis"
        elif name == "write_file":
            path    = args.get("path", "?")
            content = args.get("content", "")
            text    = f"wrote {len(content)} bytes to {path}"
        else:
            text = f"[mock] called unknown tool: {name}"

        return {
            "jsonrpc": "2.0", "id": id_,
            "result": {"content": [{"type": "text", "text": text}], "isError": False},
        }

    # Unknown request with an id → method not found
    if id_ is not None:
        return {
            "jsonrpc": "2.0", "id": id_,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    return None   # notification — no response needed


for raw_line in sys.stdin:
    line = raw_line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue

    resp = handle(msg)
    if resp is not None:
        print(json.dumps(resp), flush=True)
