"""Tests for the policy engine orchestration."""

import pytest

from gateway.app.policy.engine import (
    Decision,
    PolicyEngine,
    PolicyResult,
    PolicyRule,
    RequestContext,
    ResponseContext,
)


class AlwaysAllowRule(PolicyRule):
    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        return PolicyResult(decision=Decision.ALLOW)

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(decision=Decision.ALLOW)


class AlwaysDenyRule(PolicyRule):
    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        return PolicyResult(decision=Decision.DENY, reason="always deny")

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(decision=Decision.DENY, reason="always deny")


class SanitizeRule(PolicyRule):
    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        return PolicyResult(
            decision=Decision.SANITIZE,
            reason="sanitized",
            modifications={"arguments": {"cleaned": True}},
        )

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(
            decision=Decision.SANITIZE,
            reason="sanitized",
            modifications={"result": "scrubbed"},
        )


class ExplodingRule(PolicyRule):
    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        raise RuntimeError("boom")

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        raise RuntimeError("boom")


def _ctx() -> RequestContext:
    return RequestContext(method="tools/call", tool_name="test")


def _rctx() -> ResponseContext:
    return ResponseContext(method="tools/call", tool_name="test", result="data")


class TestPolicyEngine:
    def test_empty_engine_allows(self):
        engine = PolicyEngine(rules=[])
        assert engine.evaluate_request(_ctx()).decision == Decision.ALLOW
        assert engine.evaluate_response(_rctx()).decision == Decision.ALLOW

    def test_deny_short_circuits(self):
        engine = PolicyEngine(rules=[AlwaysDenyRule(), AlwaysAllowRule()])
        result = engine.evaluate_request(_ctx())
        assert result.decision == Decision.DENY
        assert result.reason == "always deny"

    def test_sanitize_merges_modifications(self):
        engine = PolicyEngine(rules=[SanitizeRule()])
        result = engine.evaluate_request(_ctx())
        assert result.decision == Decision.SANITIZE
        assert result.modifications == {"arguments": {"cleaned": True}}

    def test_deny_beats_sanitize(self):
        engine = PolicyEngine(rules=[SanitizeRule(), AlwaysDenyRule()])
        result = engine.evaluate_request(_ctx())
        assert result.decision == Decision.DENY

    def test_fail_closed_on_error(self):
        engine = PolicyEngine(rules=[ExplodingRule()], fail_closed=True)
        result = engine.evaluate_request(_ctx())
        assert result.decision == Decision.DENY
        assert "fail-closed" in result.reason

    def test_fail_open_on_error(self):
        engine = PolicyEngine(rules=[ExplodingRule()], fail_closed=False)
        result = engine.evaluate_request(_ctx())
        assert result.decision == Decision.ALLOW

    def test_response_deny(self):
        engine = PolicyEngine(rules=[AlwaysDenyRule()])
        result = engine.evaluate_response(_rctx())
        assert result.decision == Decision.DENY

    def test_response_sanitize(self):
        engine = PolicyEngine(rules=[SanitizeRule()])
        result = engine.evaluate_response(_rctx())
        assert result.decision == Decision.SANITIZE
        assert result.modifications == {"result": "scrubbed"}

    def test_add_rule(self):
        engine = PolicyEngine()
        engine.add_rule(AlwaysDenyRule())
        assert engine.evaluate_request(_ctx()).decision == Decision.DENY

    def test_request_context_from_mcp(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"command": "ls"},
            },
        }
        ctx = RequestContext.from_mcp_message(msg)
        assert ctx.method == "tools/call"
        assert ctx.tool_name == "run_command"
        assert ctx.arguments == {"command": "ls"}
