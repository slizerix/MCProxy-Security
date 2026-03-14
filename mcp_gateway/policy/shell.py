"""
Shell-command safety policy.

Inspects tool-call arguments that appear to execute shell commands and
enforces allowlists / blocklists to prevent destructive operations.
"""

from __future__ import annotations

import logging
import re
import shlex
from typing import Any

from mcp_gateway.config import ShellPolicyConfig
from mcp_gateway.policy.engine import Decision, PolicyResult, PolicyRule, RequestContext, ResponseContext

logger = logging.getLogger(__name__)

SHELL_TOOL_NAMES = {
    "shell", "shell.execute", "run_command", "execute_command",
    "bash", "terminal", "process.run", "exec", "run",
    "run_terminal_command",
}

COMMAND_ARG_KEYS = {"command", "cmd", "shell", "script", "args", "exec"}


def _normalize_command(raw: str) -> str:
    """Strip surrounding whitespace and collapse multiple spaces."""
    return re.sub(r"\s+", " ", raw.strip())


def _split_compound_commands(raw: str) -> list[str]:
    """Split on shell compound operators to evaluate each segment."""
    parts = re.split(r"\s*(?:&&|\|\|?|;)\s*", raw)
    return [p.strip() for p in parts if p.strip()]


def _extract_base_command(segment: str) -> str:
    """Extract the first token (the executable) from a command segment."""
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    return tokens[0] if tokens else ""


def _find_command_string(arguments: dict[str, Any]) -> str | None:
    """Try to find the shell command string in tool-call arguments."""
    for key in COMMAND_ARG_KEYS:
        if key in arguments and isinstance(arguments[key], str):
            return arguments[key]
    for v in arguments.values():
        if isinstance(v, str) and len(v) > 2:
            return v
    return None


class ShellSafetyRule(PolicyRule):
    def __init__(self, config: ShellPolicyConfig):
        self.config = config
        self._blocked_patterns = [re.compile(p, re.I) for p in config.blocked_patterns]

    def _is_shell_tool(self, ctx: RequestContext) -> bool:
        if ctx.tool_name.lower() in SHELL_TOOL_NAMES:
            return True
        if ctx.method == "tools/call" and ctx.tool_name.lower() in SHELL_TOOL_NAMES:
            return True
        return False

    def _check_command(self, raw_cmd: str) -> PolicyResult | None:
        """Return a DENY result if the command violates policy, else None."""
        cmd = _normalize_command(raw_cmd)

        for pattern in self._blocked_patterns:
            if pattern.search(cmd):
                return PolicyResult(
                    decision=Decision.DENY,
                    reason=f"Shell command matches blocked pattern: {pattern.pattern!r}",
                )

        segments = _split_compound_commands(cmd)
        for segment in segments:
            base = _extract_base_command(segment)
            if not base:
                continue

            for blocked in self.config.blocked_commands:
                blocked_parts = blocked.split()
                seg_parts = segment.split()
                if len(seg_parts) >= len(blocked_parts):
                    if [p.lower() for p in seg_parts[:len(blocked_parts)]] == [p.lower() for p in blocked_parts]:
                        return PolicyResult(
                            decision=Decision.DENY,
                            reason=f"Shell command '{base}' is in the blocked list",
                        )

            if re.search(r"\$\(|`[^`]+`", segment):
                return PolicyResult(
                    decision=Decision.DENY,
                    reason="Shell command contains subshell expansion, which is not allowed",
                )

        return None

    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        if not self._is_shell_tool(ctx):
            return PolicyResult(decision=Decision.ALLOW)

        raw_cmd = _find_command_string(ctx.arguments)
        if raw_cmd is None:
            return PolicyResult(decision=Decision.ALLOW)

        denial = self._check_command(raw_cmd)
        if denial:
            return denial

        return PolicyResult(decision=Decision.ALLOW)

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(decision=Decision.ALLOW)
