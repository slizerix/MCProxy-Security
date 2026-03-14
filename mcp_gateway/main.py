"""
MCP Firewall Gateway -- entrypoint.

Usage:
    python -m mcp_gateway.main --config config.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

Everything after '--' is treated as the upstream MCP server command.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from mcp_gateway.config import GatewayConfig, load_config
from mcp_gateway.audit import configure_logging
from mcp_gateway.transport import open_client_transport, open_upstream_transport
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.policy.pii import PIIRule
from mcp_gateway.policy.prompt_injection import PromptInjectionRule
from mcp_gateway.policy.shell import ShellSafetyRule
from mcp_gateway.proxy import MCPProxy

logger = logging.getLogger(__name__)


def _build_policy_engine(cfg: GatewayConfig) -> PolicyEngine:
    engine = PolicyEngine(fail_closed=cfg.fail_closed)

    if cfg.prompt_injection.enabled:
        engine.add_rule(PromptInjectionRule(cfg.prompt_injection))

    if cfg.shell_policy.enabled:
        engine.add_rule(ShellSafetyRule(cfg.shell_policy))

    if cfg.pii.enabled:
        engine.add_rule(PIIRule(cfg.pii))

    return engine


async def _run(cfg: GatewayConfig, upstream_cmd: list[str]) -> None:
    if not upstream_cmd and not cfg.upstream.command:
        logger.error("No upstream command specified. Use --config or pass after '--'.")
        sys.exit(1)

    cmd = upstream_cmd or cfg.upstream.command
    env = {**dict(__import__("os").environ), **cfg.upstream.env} if cfg.upstream.env else None

    logger.info("Starting upstream MCP server: %s", " ".join(cmd))
    upstream_transport, process = await open_upstream_transport(cmd, env=env)

    logger.info("Opening client (stdio) transport")
    client_transport = await open_client_transport()

    engine = _build_policy_engine(cfg)
    proxy = MCPProxy(client_transport, upstream_transport, engine)

    logger.info("MCP Firewall Gateway running -- proxying traffic")
    try:
        await proxy.run()
    finally:
        if process.returncode is None:
            process.terminate()
            await process.wait()
        logger.info("Gateway shut down")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP Firewall Gateway -- authorization proxy for MCP servers",
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        default=None,
        help="Path to gateway config YAML (default: config.yaml)",
    )
    args, upstream_cmd = parser.parse_known_args()

    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]

    cfg = load_config(args.config)
    configure_logging(cfg.logging)

    logger.info("Loaded configuration from %s", args.config or "defaults")
    asyncio.run(_run(cfg, upstream_cmd))


if __name__ == "__main__":
    main()
