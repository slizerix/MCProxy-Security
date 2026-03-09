"""Tests for the PII detection and redaction policy."""

import pytest

from gateway.app.config import PIIConfig
from gateway.app.policy.engine import Decision, RequestContext, ResponseContext
from gateway.app.policy.rules_pii import PIIDetector, PIIRule


@pytest.fixture
def config() -> PIIConfig:
    return PIIConfig()


@pytest.fixture
def detector(config: PIIConfig) -> PIIDetector:
    return PIIDetector(config)


@pytest.fixture
def rule(config: PIIConfig) -> PIIRule:
    return PIIRule(config)


class TestPIIDetector:
    def test_email_detected(self, detector: PIIDetector):
        findings = detector.scan("Contact me at john@example.com please.")
        assert any(cat == "email" for cat, _ in findings)

    def test_ssn_detected(self, detector: PIIDetector):
        findings = detector.scan("My SSN is 123-45-6789.")
        assert any(cat == "ssn" for cat, _ in findings)

    def test_phone_detected(self, detector: PIIDetector):
        findings = detector.scan("Call me at (555) 123-4567.")
        assert any(cat == "phone" for cat, _ in findings)

    def test_api_token_openai(self, detector: PIIDetector):
        findings = detector.scan("Token: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(cat == "api_token" for cat, _ in findings)

    def test_api_token_github(self, detector: PIIDetector):
        findings = detector.scan("PAT: ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        assert any(cat == "api_token" for cat, _ in findings)

    def test_api_token_aws(self, detector: PIIDetector):
        findings = detector.scan("Key: AKIAIOSFODNN7EXAMPLE")
        assert any(cat == "api_token" for cat, _ in findings)

    def test_no_pii_in_clean_text(self, detector: PIIDetector):
        findings = detector.scan("Just a normal sentence with no sensitive info.")
        assert len(findings) == 0

    def test_redaction(self, detector: PIIDetector):
        original = "Email: john@example.com, SSN: 123-45-6789"
        redacted = detector.redact(original)
        assert "john@example.com" not in redacted
        assert "123-45-6789" not in redacted
        assert "***REDACTED***" in redacted

    def test_custom_pattern(self):
        cfg = PIIConfig(
            categories=[],
            custom_patterns={"employee_id": r"EMP-\d{6}"},
        )
        det = PIIDetector(cfg)
        findings = det.scan("Employee EMP-123456 submitted a request.")
        assert any(cat == "employee_id" for cat, _ in findings)


class TestPIIRule:
    def test_request_with_pii_sanitized(self, rule: PIIRule):
        ctx = RequestContext(
            method="tools/call",
            tool_name="send_email",
            arguments={"body": "Please contact john@example.com about SSN 123-45-6789"},
        )
        result = rule.evaluate_request(ctx)
        assert result.decision == Decision.SANITIZE
        assert "***REDACTED***" in result.modifications["arguments"]["body"]
        assert "john@example.com" not in result.modifications["arguments"]["body"]

    def test_request_without_pii_allowed(self, rule: PIIRule):
        ctx = RequestContext(
            method="tools/call",
            tool_name="read_file",
            arguments={"path": "/tmp/notes.txt"},
        )
        result = rule.evaluate_request(ctx)
        assert result.decision == Decision.ALLOW

    def test_response_with_pii_sanitized(self, rule: PIIRule):
        ctx = ResponseContext(
            method="tools/call",
            tool_name="read_file",
            result={"content": "User email: admin@company.com, token: sk-abcdefghijklmnopqrstuvwxyz"},
        )
        result = rule.evaluate_response(ctx)
        assert result.decision == Decision.SANITIZE
        redacted_content = result.modifications["result"]["content"]
        assert "admin@company.com" not in redacted_content
        assert "sk-" not in redacted_content

    def test_response_without_pii_allowed(self, rule: PIIRule):
        ctx = ResponseContext(
            method="tools/call",
            tool_name="read_file",
            result={"content": "Hello world"},
        )
        result = rule.evaluate_response(ctx)
        assert result.decision == Decision.ALLOW

    def test_nested_structure_scanned(self, rule: PIIRule):
        ctx = RequestContext(
            method="tools/call",
            tool_name="api_call",
            arguments={
                "headers": {"Authorization": "Bearer sk-abcdefghijklmnopqrstuvwxyz"},
                "data": {"users": [{"email": "test@example.com"}]},
            },
        )
        result = rule.evaluate_request(ctx)
        assert result.decision == Decision.SANITIZE
