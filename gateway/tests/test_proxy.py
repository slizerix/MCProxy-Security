"""Integration-style tests for the MCP proxy routing logic."""

import asyncio
import json

import pytest

from gateway.app.policy.engine import Decision, PolicyEngine, PolicyResult, PolicyRule, RequestContext, ResponseContext
from gateway.app.proxy import MCPProxy, _jsonrpc_error


class DenyShellRule(PolicyRule):
    """Deny any tools/call to 'run_command'."""

    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        if ctx.tool_name == "run_command":
            return PolicyResult(decision=Decision.DENY, reason="shell blocked")
        return PolicyResult(decision=Decision.ALLOW)

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(decision=Decision.ALLOW)


class RedactResponseRule(PolicyRule):
    """Sanitize any response by replacing the result."""

    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        return PolicyResult(decision=Decision.ALLOW)

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(
            decision=Decision.SANITIZE,
            reason="redacted",
            modifications={"result": "***REDACTED***"},
        )


def _make_transport_pair():
    """Create an in-memory StreamReader/Writer pair for testing."""
    from gateway.app.mcp_transport import StdioTransport

    reader = asyncio.StreamReader()
    # Simple writable buffer that we can inspect
    written: list[bytes] = []

    class FakeWriter:
        def write(self, data: bytes):
            written.append(data)

        async def drain(self):
            pass

    transport = StdioTransport(reader, FakeWriter(), label="test")  # type: ignore[arg-type]
    return transport, reader, written


@pytest.mark.asyncio
async def test_allowed_request_forwarded():
    """An allowed request passes through to upstream and response comes back."""
    client_transport, client_reader, client_written = _make_transport_pair()
    upstream_transport, upstream_reader, upstream_written = _make_transport_pair()

    engine = PolicyEngine(rules=[])
    proxy = MCPProxy(client_transport, upstream_transport, engine)

    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    client_reader.feed_data((json.dumps(request) + "\n").encode())
    client_reader.feed_eof()

    response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    upstream_reader.feed_data((json.dumps(response) + "\n").encode())
    upstream_reader.feed_eof()

    await proxy.run()

    # Request was forwarded to upstream
    assert len(upstream_written) == 1
    forwarded = json.loads(upstream_written[0].decode())
    assert forwarded["method"] == "tools/list"

    # Response was forwarded to client
    assert len(client_written) == 1
    returned = json.loads(client_written[0].decode())
    assert returned["result"] == {"tools": []}


@pytest.mark.asyncio
async def test_denied_request_returns_error():
    """A denied request never reaches upstream; client gets an error."""
    client_transport, client_reader, client_written = _make_transport_pair()
    upstream_transport, upstream_reader, upstream_written = _make_transport_pair()

    engine = PolicyEngine(rules=[DenyShellRule()])
    proxy = MCPProxy(client_transport, upstream_transport, engine)

    request = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}},
    }
    client_reader.feed_data((json.dumps(request) + "\n").encode())
    client_reader.feed_eof()

    upstream_reader.feed_eof()

    await proxy.run()

    # Nothing was sent to upstream
    assert len(upstream_written) == 0

    # Client received an error
    assert len(client_written) == 1
    err = json.loads(client_written[0].decode())
    assert "error" in err
    assert err["id"] == 42
    assert "shell blocked" in err["error"]["message"]


@pytest.mark.asyncio
async def test_response_sanitization():
    """A response with PII-like content is sanitized before reaching client."""
    client_transport, client_reader, client_written = _make_transport_pair()
    upstream_transport, upstream_reader, upstream_written = _make_transport_pair()

    engine = PolicyEngine(rules=[RedactResponseRule()])
    proxy = MCPProxy(client_transport, upstream_transport, engine)

    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {}}}
    client_reader.feed_data((json.dumps(request) + "\n").encode())
    client_reader.feed_eof()

    response = {"jsonrpc": "2.0", "id": 1, "result": "secret data here"}
    upstream_reader.feed_data((json.dumps(response) + "\n").encode())
    upstream_reader.feed_eof()

    await proxy.run()

    assert len(client_written) == 1
    returned = json.loads(client_written[0].decode())
    assert returned["result"] == "***REDACTED***"


@pytest.mark.asyncio
async def test_notification_passes_through():
    """Notifications (no id) should pass through without policy checks."""
    client_transport, client_reader, client_written = _make_transport_pair()
    upstream_transport, upstream_reader, upstream_written = _make_transport_pair()

    engine = PolicyEngine(rules=[DenyShellRule()])
    proxy = MCPProxy(client_transport, upstream_transport, engine)

    notification = {"jsonrpc": "2.0", "method": "initialized"}
    client_reader.feed_data((json.dumps(notification) + "\n").encode())
    client_reader.feed_eof()
    upstream_reader.feed_eof()

    await proxy.run()

    assert len(upstream_written) == 1
    forwarded = json.loads(upstream_written[0].decode())
    assert forwarded["method"] == "initialized"


def test_jsonrpc_error_format():
    err = _jsonrpc_error(42, -32600, "blocked")
    assert err["jsonrpc"] == "2.0"
    assert err["id"] == 42
    assert err["error"]["code"] == -32600
    assert err["error"]["message"] == "blocked"
