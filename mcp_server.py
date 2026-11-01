"""Tiny MCP server (stdio, no dependencies) exposing a `call_me` tool."""
import json
import sys

from notify import alert

TOOLS = [{
    "name": "call_me",
    "description": ("Ring the user's phone (Linphone app) to get their attention, "
                    "e.g. when a long task finishes or you need their input. "
                    "The message is shown as the caller name on the phone. "
                    "If the call fails, sends an urgent ntfy.sh push instead."),
    "inputSchema": {
        "type": "object",
        "properties": {
            "message": {"type": "string", "description": "Short text shown as caller name (max ~60 chars)"},
            "ring_seconds": {"type": "integer", "description": "How long to ring (default 30)"},
        },
    },
}]


def reply(id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    msg["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    method, id_ = req.get("method"), req.get("id")
    if id_ is None:  # notification
        continue
    if method == "initialize":
        reply(id_, {"protocolVersion": req["params"].get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "phone-caller", "version": "1.0"}})
    elif method == "tools/list":
        reply(id_, {"tools": TOOLS})
    elif method == "tools/call":
        args = req["params"].get("arguments") or {}
        try:
            out = alert(args.get("message") or "Claude", int(args.get("ring_seconds") or 30))
            reply(id_, {"content": [{"type": "text", "text": out}]})
        except Exception as e:
            reply(id_, {"content": [{"type": "text", "text": f"call error: {e}"}], "isError": True})
    elif method == "ping":
        reply(id_, {})
    else:
        reply(id_, error={"code": -32601, "message": f"unknown method {method}"})
