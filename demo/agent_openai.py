#!/usr/bin/env python3
"""
Aegis real-time demo — ChatGPT (OpenAI API) + Mock MCP Server.

Same architecture as agent_claude.py but uses OpenAI function-calling.

Usage:
  # Terminal 1 — start Aegis
  cargo run -p aegis-api

  # Terminal 2 — run this agent
  export OPENAI_API_KEY=sk-...
  python3 demo/agent_openai.py
"""

import os, sys, json, subprocess, uuid, urllib.request, urllib.error, time

# ── config ────────────────────────────────────────────────────────────────────

AEGIS_URL   = "http://localhost:3000"
AGENT_ID    = "gpt-agent"
MODEL       = "gpt-4o"

USER_PROMPT = (
    "Please do these three things in order:\n"
    "1. Use the echo function with message: 'Aegis is watching every call'\n"
    "2. Use the add function to compute 42 + 58\n"
    "3. Use the get_info function to get the server version\n"
    "Report what each function returned."
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

# ── inline mock MCP server ────────────────────────────────────────────────────

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
        return json.loads(self._proc.stdout.readline())

    def handshake(self):
        self._id += 1
        self._send({"jsonrpc":"2.0","id":self._id,"method":"initialize",
                    "params":{"protocolVersion":"2024-11-05","capabilities":{},
                              "clientInfo":{"name":"demo-agent","version":"1.0"}}})
        self._recv()
        self._send({"jsonrpc":"2.0","method":"notifications/initialized"})
        self._id += 1
        self._send({"jsonrpc":"2.0","id":self._id,"method":"tools/list","params":{}})
        return self._recv()["result"]["tools"]

    def call_tool(self, name, arguments):
        self._id += 1
        self._send({"jsonrpc":"2.0","id":self._id,"method":"tools/call",
                    "params":{"name":name,"arguments":arguments}})
        resp = self._recv()
        if "error" in resp:
            return None, resp["error"].get("message","unknown error")
        content = resp["result"].get("content", [])
        return (content[0].get("text","") if content else ""), None

    def close(self):
        self._proc.stdin.close()
        self._proc.wait()


# ── Aegis REST client ─────────────────────────────────────────────────────────

class AegisClient:
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
        if max_uses:
            body["max_uses"] = max_uses
        return self._post("/tokens", body)

    def enforce(self, agent_id, tool_name, resource, token_id, parameters=None):
        return self._post("/enforce", {
            "agent_id":   agent_id,
            "tool_name":  tool_name,
            "action":     "execute",
            "resource":   resource,
            "parameters": parameters or {},
            "token_id":   str(token_id),
        })

    def audit(self, limit=50):
        return self._get(f"/audit?limit={limit}")

    def ping(self):
        self._get("/audit?limit=1")


# ── OpenAI API helper (no SDK required) ──────────────────────────────────────

def openai_chat(api_key, model, messages, tools):
    """Call the OpenAI chat completions API without the openai package."""
    body = {
        "model":    model,
        "messages": messages,
        "tools":    tools,
    }
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=data,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


# ── main demo ─────────────────────────────────────────────────────────────────

def run():
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print(red("✗  OPENAI_API_KEY not set."))
        sys.exit(1)

    print()
    print(bold("╔══════════════════════════════════════════════════════════╗"))
    print(bold("║     AEGIS  ·  Real-Time LLM Enforcement Demo (GPT-4o)    ║"))
    print(bold("╚══════════════════════════════════════════════════════════╝"))

    aegis = AegisClient(AEGIS_URL)
    try:
        aegis.ping()
        print(green("✓  Aegis API reachable on :3000"))
    except Exception as e:
        print(red("✗  Cannot reach Aegis API on :3000"))
        print(red(f"   Error: {e}"))
        print(yellow("   Start it with:  cargo run -p aegis-api"))
        sys.exit(1)

    # ── issue tokens ─────────────────────────────────────────────────────────
    banner("Step 1 · Issue capability tokens")
    echo_token = aegis.issue_token(AGENT_ID, "tool://echo", ["execute"], max_uses=3)
    print(green(f"  ✓  Token issued for tool://echo  (max_uses=3)"))
    print(dim (f"     id={echo_token['id']}"))
    print(yellow("  ⚠   No token for 'add' or 'get_info' — those calls will be DENIED"))

    token_map = {"echo": echo_token["id"]}

    # ── start mock MCP server ─────────────────────────────────────────────────
    banner("Step 2 · Start mock MCP server")
    mcp   = MockMcpServer()
    tools = mcp.handshake()
    print(green(f"  ✓  Mock MCP server ready — tools: {[t['name'] for t in tools]}"))

    # OpenAI function format
    openai_tools = [
        {
            "type": "function",
            "function": {
                "name":        t["name"],
                "description": t.get("description", ""),
                "parameters":  t.get("inputSchema", {"type":"object","properties":{}}),
            },
        }
        for t in tools
    ]

    # ── agentic loop ──────────────────────────────────────────────────────────
    banner("Step 3 · GPT-4o agentic loop")
    print(dim(f"  Prompt: {USER_PROMPT}"))
    print()

    messages = [{"role": "user", "content": USER_PROMPT}]
    stats    = {"allow": 0, "deny": 0}

    while True:
        print(blue("  ↻  Calling GPT-4o..."), end="", flush=True)
        resp        = openai_chat(api_key, MODEL, messages, openai_tools)
        choice      = resp["choices"][0]
        finish      = choice["finish_reason"]
        msg         = choice["message"]
        print(f" {dim('finish_reason=' + finish)}")

        messages.append(msg)

        if finish == "stop":
            break

        if finish != "tool_calls":
            print(yellow(f"  Unexpected finish_reason: {finish}"))
            break

        for tc in msg.get("tool_calls", []):
            tool   = tc["function"]["name"]
            args   = json.loads(tc["function"].get("arguments", "{}"))
            tc_id  = tc["id"]

            print()
            print(bold(f"  🔧  GPT-4o → {tool}({json.dumps(args)})"))

            token_id = token_map.get(tool, str(uuid.uuid4()))
            if tool not in token_map:
                print(yellow(f"  ⚠   No token for '{tool}' — Aegis will deny"))

            t0          = time.perf_counter()
            enf         = aegis.enforce(AGENT_ID, tool, f"tool://{tool}", token_id)
            elapsed_ms  = (time.perf_counter() - t0) * 1000
            decision    = enf["decision"]
            reason      = enf["audit"]["reason"]
            latency_us  = enf["audit"]["latency_us"]

            if decision == "allow":
                stats["allow"] += 1
                print(green(f"  🛡   Aegis → ALLOWED  "
                            f"[enforce: {elapsed_ms:.1f}ms · engine: {latency_us}µs]"))
                result, err = mcp.call_tool(tool, args)
                if err:
                    content = f"[MCP error: {err}]"
                    print(red(f"  ✗   MCP error: {err}"))
                else:
                    content = result
                    print(green(f"  ✅  Result: {result}"))
            else:
                stats["deny"] += 1
                print(red(f"  🛡   Aegis → BLOCKED  [reason: {reason}]"))
                print(red(f"  ❌  Not forwarded to MCP server"))
                content = f"[BLOCKED by Aegis: {reason}]"

            # OpenAI expects tool results as role="tool" messages
            messages.append({
                "role":         "tool",
                "tool_call_id": tc_id,
                "content":      content,
            })

    # ── final answer ──────────────────────────────────────────────────────────
    banner("GPT-4o Final Answer")
    final_content = msg.get("content") or ""
    print(f"  {final_content}")

    # ── audit log ─────────────────────────────────────────────────────────────
    banner("Aegis Audit Log")
    entries = aegis.audit(limit=20)
    print(f"  {'DECISION':<7}  {'TOOL':<14}  {'AGENT':<12}  {'LATENCY':>8}  REASON")
    print(dim("  " + "-" * 64))
    for e in entries:
        icon = green("ALLOW") if e["decision"] == "allow" else red("DENY ")
        print(f"  {icon}  {e['tool_name']:<14}  {e['agent_id']:<12}  "
              f"{str(e['latency_us'])+'µs':>8}  {e['reason']}")

    banner("Summary")
    print(f"  Tool calls:  {stats['allow'] + stats['deny']}")
    print(green(f"  Allowed:     {stats['allow']}"))
    print(red  (f"  Blocked:     {stats['deny']}"))
    print()

    mcp.close()


if __name__ == "__main__":
    run()
