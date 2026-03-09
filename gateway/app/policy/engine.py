"""
Policy engine: evaluates a pipeline of rules against request/response contexts
and produces allow / deny / sanitize decisions.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SANITIZE = "sanitize"


class PolicyResult(BaseModel):
    """The outcome of evaluating a single policy rule."""
    decision: Decision = Decision.ALLOW
    reason: str = ""
    score: float = 0.0
    modifications: dict[str, Any] = Field(default_factory=dict)


class RequestContext(BaseModel):
    """Normalized view of an inbound MCP request for policy evaluation."""
    method: str = ""
    tool_name: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_message: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_mcp_message(cls, msg: dict[str, Any]) -> RequestContext:
        method = msg.get("method", "")
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        return cls(
            method=method,
            tool_name=tool_name,
            params=params,
            arguments=arguments,
            raw_message=msg,
        )


class ResponseContext(BaseModel):
    """Normalized view of an outbound MCP response for policy evaluation."""
    method: str = ""
    tool_name: str = ""
    result: Any = None
    raw_message: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_mcp_response(
        cls, msg: dict[str, Any], originating_method: str = "", tool_name: str = ""
    ) -> ResponseContext:
        return cls(
            method=originating_method,
            tool_name=tool_name,
            result=msg.get("result"),
            raw_message=msg,
        )


class PolicyRule(ABC):
    """Base class for all policy rules."""

    @abstractmethod
    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        ...

    @abstractmethod
    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        ...


class PolicyEngine:
    """Runs an ordered pipeline of PolicyRule instances and returns the
    most restrictive decision."""

    def __init__(self, rules: list[PolicyRule] | None = None, fail_closed: bool = True):
        self.rules: list[PolicyRule] = rules or []
        self.fail_closed = fail_closed

    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        """Run every rule against the request; return the first non-ALLOW or
        merge SANITIZE modifications."""
        merged_mods: dict[str, Any] = {}

        for rule in self.rules:
            try:
                result = rule.evaluate_request(ctx)
            except Exception:
                logger.exception("Policy rule %s raised during request evaluation", type(rule).__name__)
                if self.fail_closed:
                    return PolicyResult(decision=Decision.DENY, reason="Internal policy error (fail-closed)")
                continue

            if result.decision == Decision.DENY:
                logger.info("Request DENIED by %s: %s", type(rule).__name__, result.reason)
                return result

            if result.decision == Decision.SANITIZE:
                merged_mods.update(result.modifications)

        if merged_mods:
            return PolicyResult(
                decision=Decision.SANITIZE,
                reason="Request parameters sanitized",
                modifications=merged_mods,
            )

        return PolicyResult(decision=Decision.ALLOW)

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        """Run every rule against the response; return the first non-ALLOW or
        merge SANITIZE modifications."""
        merged_mods: dict[str, Any] = {}

        for rule in self.rules:
            try:
                result = rule.evaluate_response(ctx)
            except Exception:
                logger.exception("Policy rule %s raised during response evaluation", type(rule).__name__)
                if self.fail_closed:
                    return PolicyResult(decision=Decision.DENY, reason="Internal policy error (fail-closed)")
                continue

            if result.decision == Decision.DENY:
                logger.info("Response DENIED by %s: %s", type(rule).__name__, result.reason)
                return result

            if result.decision == Decision.SANITIZE:
                merged_mods.update(result.modifications)

        if merged_mods:
            return PolicyResult(
                decision=Decision.SANITIZE,
                reason="Response content sanitized",
                modifications=merged_mods,
            )

        return PolicyResult(decision=Decision.ALLOW)
