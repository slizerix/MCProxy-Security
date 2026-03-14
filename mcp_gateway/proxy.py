"""
MCP Proxy -- routes JSON-RPC messages between the downstream AI client and the
upstream MCP server, running each message through the policy engine.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from typing import Any

from mcp_gateway.transport import StdioTransport
from mcp_gateway.policy.engine import (
    Decision,
    PolicyEngine,
    PolicyResult,
    RequestContext,
    ResponseContext,
)

logger = logging.getLogger(__name__)

TOOL_CALL_METHODS = {"tools/call"}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _is_request(msg: dict[str, Any]) -> bool:
    return "method" in msg


def _is_notification(msg: dict[str, Any]) -> bool:
    return "method" in msg and "id" not in msg


def _apply_request_modifications(msg: dict[str, Any], mods: dict[str, Any]) -> dict[str, Any]:
    """Return a modified copy of the message with policy-dictated changes."""
    msg = copy.deepcopy(msg)
    if "arguments" in mods:
        msg.setdefault("params", {})["arguments"] = mods["arguments"]
    if "params" in mods:
        msg["params"] = mods["params"]
    return msg


def _apply_response_modifications(msg: dict[str, Any], mods: dict[str, Any]) -> dict[str, Any]:
    msg = copy.deepcopy(msg)
    if "result" in mods:
        msg["result"] = mods["result"]
    return msg


class MCPProxy:
    """Bidirectional MCP proxy with policy enforcement."""

    def __init__(
        self,
        client_transport: StdioTransport,
        upstream_transport: StdioTransport,
        policy_engine: PolicyEngine,
    ):
        self.client = client_transport
        self.upstream = upstream_transport
        self.engine = policy_engine
        self._pending: dict[Any, dict[str, str]] = {}

    async def run(self) -> None:
        """Run both forwarding loops concurrently until one side closes."""
        await asyncio.gather(
            self._client_to_upstream(),
            self._upstream_to_client(),
        )

    async def _client_to_upstream(self) -> None:
        """Read from client, apply request policies, forward to upstream."""
        while True:
            msg = await self.client.read_message()
            if msg is None:
                logger.info("Client disconnected")
                break

            if _is_notification(msg):
                await self.upstream.write_message(msg)
                continue

            if not _is_request(msg):
                await self.upstream.write_message(msg)
                continue

            ctx = RequestContext.from_mcp_message(msg)
            result: PolicyResult = self.engine.evaluate_request(ctx)

            if result.decision == Decision.DENY:
                logger.warning("Blocked request [%s] %s: %s", msg.get("id"), ctx.method, result.reason)
                err = _jsonrpc_error(msg.get("id"), -32600, f"Blocked by policy: {result.reason}")
                await self.client.write_message(err)
                continue

            if result.decision == Decision.SANITIZE:
                msg = _apply_request_modifications(msg, result.modifications)

            self._pending[msg.get("id")] = {
                "method": ctx.method,
                "tool_name": ctx.tool_name,
            }

            await self.upstream.write_message(msg)

    async def _upstream_to_client(self) -> None:
        """Read from upstream, apply response policies, forward to client."""
        while True:
            msg = await self.upstream.read_message()
            if msg is None:
                logger.info("Upstream disconnected")
                break

            if _is_notification(msg):
                await self.client.write_message(msg)
                continue

            req_id = msg.get("id")
            meta = self._pending.pop(req_id, {"method": "", "tool_name": ""})

            ctx = ResponseContext.from_mcp_response(
                msg,
                originating_method=meta.get("method", ""),
                tool_name=meta.get("tool_name", ""),
            )
            result: PolicyResult = self.engine.evaluate_response(ctx)

            if result.decision == Decision.DENY:
                logger.warning("Blocked response for request %s: %s", req_id, result.reason)
                err = _jsonrpc_error(req_id, -32600, f"Response blocked by policy: {result.reason}")
                await self.client.write_message(err)
                continue

            if result.decision == Decision.SANITIZE:
                msg = _apply_response_modifications(msg, result.modifications)

            await self.client.write_message(msg)
