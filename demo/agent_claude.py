#!/usr/bin/env python3
"""
Aegis real-time demo — Claude (Anthropic API) + Mock MCP Server.

What this shows:
  - Claude requests tool calls (echo, add, get_info)
  - Aegis evaluates each call BEFORE it runs (allow / deny)
  - Allowed calls execute; denied calls are blocked
  - Full audit trail printed at the end

Architecture:
  You → Claude API → tool_use request
                        ↓
                  POST /enforce  →  Aegis API (:3000)
                        ↓ ALLOW          ↓ DENY
                  Mock MCP server    BLOCKED + reason
                        ↓
                  result → Claude → final answer

Usage:
  # Terminal 1 — start Aegis
  cargo run -p aegis-api

  # Terminal 2 — run this agent
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 demo/agent_claude.py
"""

import os, sys, json, subprocess, uuid, urllib.request, urllib.error, time

# ── config ────────────────────────────────────────────────────────────────────

AEGIS_URL  = "http://localhost:3000"
AGENT_ID   = "claude-agent"
MODEL      = "claude-opus-4-6"

# Prompt given to Claude. It will use echo, then try add (which is blocked).
USER_PROMPT = (
    "Please do these three things in order:\n"
    "1. Use the echo tool with message: 'Aegis is watching every call'\n"
    "2. Use the add tool to compute 42 + 58\n"
    "3. Use the get_info tool to get the server version\n"
    "Report what each tool returned."
)

# ── colors ────────────────────────────────────────────────────────────────────

def _c(text, *codes):
    return "\033[" + ";".join(codes) + "m" + str(text) + "\033[0m"

def green(t):  return _c(t, "92")
def red(t):    return _c(t, "91")
def yellow(t): return _c(t, "93")
def blue(t):   return _c(t, "94")
def cyan(t):   return _c(t, "96")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")

def banner(title):
    print()
    print(cyan("─" * 60))
    print(cyan(f"  {title}"))
    print(cyan("─" * 60))

# ── inline mock MCP server (spawned as a subprocess) ─────────────────────────

_MCP_SCRIPT = r"""
import sys, json
TOOLS = [
    {"name":"echo","description":"Echoes the message back.",
     "inputSchema":{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}},
    {"name":"add","description":"Adds two numbers a and b.",
     "inputSchema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}},
    {"name":"get_info","description":"Returns mock server version.",
     "inputSchema":{"type":"object","properties":{}}}
]
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:    msg = json.loads(line)
    except: continue
    method = msg.get("method","")
    id_    = msg.get("id")
    if method == "initialize":
        r = {"jsonrpc":"2.0","id":id_,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"mock-mcp","version":"0.1.0"}}}
    elif method == "tools/list":
        r = {"jsonrpc":"2.0","id":id_,"result":{"tools":TOOLS}}
    elif method == "tools/call":
        p    = msg.get("params",{})
        name = p.get("name","")
        args = p.get("arguments",{})
        if   name == "echo":     text = str(args.get("message",""))
        elif name == "add":      text = str(args.get("a",0) + args.get("b",0))
        elif name == "get_info": text = "mock-mcp v0.1.0"
        else:                    text = "called " + name
        r = {"jsonrpc":"2.0","id":id_,"result":{"content":[{"type":"text","text":text}],"isError":False}}
    elif id_ is not None:
        r = {"jsonrpc":"2.0","id":id_,"error":{"code":-32601,"message":"Method not found"}}
    else:
        continue
    print(json.dumps(r), flush=True)
"""

class MockMcpServer:
    """Inline mock MCP server over stdio."""

    def __init__(self):
        self._proc = subprocess.Popen(
            ["python3", "-c", _MCP_SCRIPT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1,
        )
        self._id = 0

    def _send(self, msg):
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

    def _recv(self):
        line = self._proc.stdout.readline()
        return json.loads(line)

    def handshake(self):
        self._id += 1
        self._send({"jsonrpc":"2.0","id":self._id,"method":"initialize",
                    "params":{"protocolVersion":"2024-11-05","capabilities":{},
                              "clientInfo":{"name":"demo-agent","version":"1.0"}}})
        self._recv()  # initialize response
        self._send({"jsonrpc":"2.0","method":"notifications/initialized"})
        self._id += 1
        self._send({"jsonrpc":"2.0","id":self._id,"method":"tools/list","params":{}})
        resp = self._recv()
        return resp["result"]["tools"]

    def call_tool(self, name, arguments):
        self._id += 1
        self._send({"jsonrpc":"2.0","id":self._id,"method":"tools/call",
                    "params":{"name":name,"arguments":arguments}})
        resp = self._recv()
        if "error" in resp:
            return None, resp["error"].get("message","unknown error")
        content = resp["result"].get("content", [])
        text = content[0].get("text", "") if content else ""
        return text, None

    def close(self):
        self._proc.stdin.close()
        self._proc.wait()


# ── Aegis REST client ─────────────────────────────────────────────────────────

class AegisClient:
    """Thin wrapper around the Aegis REST API."""

    def __init__(self, base_url):
        self._base = base_url.rstrip("/")

    def _post(self, path, body):
        data = json.dumps(body).encode()
        req  = urllib.request.Request(
            self._base + path, data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def _get(self, path):
        with urllib.request.urlopen(self._base + path, timeout=5) as r:
            return json.loads(r.read())

    def issue_token(self, subject, resource, actions, ttl_secs=3600, max_uses=None):
        body = {"subject": subject, "resource": resource,
                "actions": actions, "ttl_secs": ttl_secs}
        if max_uses is not None:
            body["max_uses"] = max_uses
        return self._post("/tokens", body)

    def enforce(self, agent_id, tool_name, resource, token_id, parameters=None):
        return self._post("/enforce", {
            "agent_id":  agent_id,
            "tool_name": tool_name,
            "action":    "execute",
            "resource":  resource,
            "parameters": parameters or {},
            "token_id":  str(token_id),
        })

    def audit(self, limit=50):
        return self._get(f"/audit?limit={limit}")

    def ping(self):
        self._get("/audit?limit=1")


# ── main demo ─────────────────────────────────────────────────────────────────

def run():
    try:
        import anthropic
    except ImportError:
        print(red("✗  anthropic package missing.  Run:  pip install anthropic"))
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print(red("✗  ANTHROPIC_API_KEY not set."))
        sys.exit(1)

    print()
    print(bold("╔══════════════════════════════════════════════════════════╗"))
    print(bold("║         AEGIS  ·  Real-Time LLM Enforcement Demo         ║"))
    print(bold("╚══════════════════════════════════════════════════════════╝"))

    # ── 1. verify Aegis is up ────────────────────────────────────────────────
    aegis = AegisClient(AEGIS_URL)
    try:
        aegis.ping()
        print(green("✓  Aegis API reachable on :3000"))
    except Exception as e:
        print(red("✗  Cannot reach Aegis API on :3000"))
        print(red(f"   Error: {e}"))
        print(yellow("   Start it with:  cargo run -p aegis-api"))
        sys.exit(1)

    # ── 2. issue capability tokens ───────────────────────────────────────────
    banner("Step 1 · Issue capability tokens")

    # Grant echo — limited to 3 uses so we can demo exhaustion later
    echo_token = aegis.issue_token(
        subject=AGENT_ID,
        resource="tool://echo",
        actions=["execute"],
        ttl_secs=3600,
        max_uses=3,
    )
    print(green(f"  ✓  Token issued for tool://echo"))
    print(dim (f"     id={echo_token['id']}  max_uses=3"))

    # Intentionally NO token for "add" or "get_info" → those calls will be DENIED

    # token_map: tool name → token UUID (only tools we have tokens for)
    token_map = {
        "echo": echo_token["id"],
        # "add" and "get_info" are absent → Aegis will deny them
    }

    # ── 3. start mock MCP server ─────────────────────────────────────────────
    banner("Step 2 · Start mock MCP server")
    mcp   = MockMcpServer()
    tools = mcp.handshake()
    names = [t["name"] for t in tools]
    print(green(f"  ✓  Mock MCP server ready"))
    print(dim (f"     tools: {names}"))

    # ── 4. build Anthropic tool list ─────────────────────────────────────────
    anthropic_tools = [
        {
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": t.get("inputSchema", {"type": "object", "properties": {}}),
        }
        for t in tools
    ]

    # ── 5. agentic loop ───────────────────────────────────────────────────────
    banner("Step 3 · Claude agentic loop")
    print(dim(f"  Prompt: {USER_PROMPT}"))
    print()

    client   = anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": USER_PROMPT}]

    stats = {"allow": 0, "deny": 0}

    while True:
        print(blue("  ↻  Calling Claude..."), end="", flush=True)
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            tools=anthropic_tools,
            messages=messages,
        )
        print(f" {dim('stop_reason=' + response.stop_reason)}")

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            break

        if response.stop_reason != "tool_use":
            print(yellow(f"  Unexpected stop_reason: {response.stop_reason}"))
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool   = block.name
            args   = block.input
            res_id = f"tool://{tool}"

            print()
            print(bold(f"  🔧  Claude → {tool}({json.dumps(args)})"))

            # ── Aegis enforcement check ──────────────────────────────────────
            token_id = token_map.get(tool)
            if token_id is None:
                # No token at all — generate a random UUID; Aegis will deny
                # because the token doesn't exist in its store.
                token_id = str(uuid.uuid4())
                print(yellow(f"  ⚠   No token issued for '{tool}' — Aegis will deny"))

            t0 = time.perf_counter()
            enforce_resp = aegis.enforce(
                agent_id=AGENT_ID,
                tool_name=tool,
                resource=res_id,
                token_id=token_id,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000

            decision   = enforce_resp["decision"]
            reason     = enforce_resp["audit"]["reason"]
            latency_us = enforce_resp["audit"]["latency_us"]

            if decision == "allow":
                stats["allow"] += 1
                print(green(f"  🛡   Aegis → ALLOWED  "
                            f"[enforce: {elapsed_ms:.1f}ms · engine: {latency_us}µs]"))

                # Forward to mock MCP server
                result, err = mcp.call_tool(tool, args)
                if err:
                    print(red(f"  ✗   MCP error: {err}"))
                    content = f"[MCP error: {err}]"
                else:
                    print(green(f"  ✅  Result: {result}"))
                    content = result

                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     content,
                })

            else:
                stats["deny"] += 1
                print(red(f"  🛡   Aegis → BLOCKED  [reason: {reason}]"))
                print(red(f"  ❌  Tool call not forwarded to MCP server"))

                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     f"[BLOCKED by Aegis: {reason}]",
                    "is_error":    True,
                })

        messages.append({"role": "user", "content": tool_results})

    # ── 6. Claude's final answer ──────────────────────────────────────────────
    banner("Claude's Final Answer")
    for block in response.content:
        if hasattr(block, "text"):
            print(f"  {block.text}")

    # ── 7. Aegis audit log ────────────────────────────────────────────────────
    banner("Aegis Audit Log")
    entries = aegis.audit(limit=20)
    if not entries:
        print(dim("  (no entries)"))
    else:
        print(f"  {'DECISION':<7}  {'TOOL':<14}  {'AGENT':<14}  {'LATENCY':>8}  REASON")
        print(dim("  " + "-" * 66))
        for e in entries:
            icon = green("ALLOW") if e["decision"] == "allow" else red("DENY ")
            row  = (f"  {icon}  "
                    f"{e['tool_name']:<14}  "
                    f"{e['agent_id']:<14}  "
                    f"{str(e['latency_us']) + 'µs':>8}  "
                    f"{e['reason']}")
            print(row)

    # ── 8. summary ────────────────────────────────────────────────────────────
    banner("Summary")
    total = stats["allow"] + stats["deny"]
    print(f"  Tool calls:  {total}")
    print(green(f"  Allowed:     {stats['allow']}"))
    print(red  (f"  Blocked:     {stats['deny']}"))
    print()
    print(dim("  Live audit:  curl http://localhost:3000/audit | python3 -m json.tool"))
    print(dim("  Metrics:     curl http://localhost:3000/metrics"))
    print()

    mcp.close()


if __name__ == "__main__":
    run()
