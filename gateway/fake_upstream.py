"""
Fake MCP upstream server for smoke-testing the gateway.

Speaks newline-delimited JSON-RPC over stdio. Responds to:
  - initialize
  - tools/list  (advertises a few fake tools)
  - tools/call  (echoes back the arguments it received)
"""

import json
import sys


TOOLS = [
    {
        "name": "run_command",
        "description": "Execute a shell command",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read file contents",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "body"],
        },
    },
]


def handle(msg: dict) -> dict | None:
    method = msg.get("method", "")
    req_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-upstream", "version": "0.1.0"},
            },
        }

    if method == "initialized":
        return None  # notification, no response

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        # Simulate tool output — echo whatever we received
        output_text = f"[fake-upstream] Tool '{tool_name}' executed with: {json.dumps(arguments)}"

        # For read_file, simulate returning content that contains PII
        if tool_name == "read_file":
            output_text = (
                "File contents:\n"
                "Name: John Doe\n"
                "Email: john.doe@acmecorp.com\n"
                "SSN: 123-45-6789\n"
                "API Key: sk-abc123def456ghi789jkl012mno345pqr678\n"
            )

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": output_text}],
            },
        }

    # Unknown method — return a generic error
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
