"""
PII / secret detection and redaction policy.

Scans tool-call arguments (outbound) and responses (inbound) for personally
identifiable information and sensitive secrets, redacting or blocking as
configured.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any

from mcp_gateway.config import PIIConfig
from mcp_gateway.policy.engine import Decision, PolicyResult, PolicyRule, RequestContext, ResponseContext

logger = logging.getLogger(__name__)

_BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "api_token": re.compile(
        r"\b("
        r"sk-[a-zA-Z0-9]{20,}"
        r"|xoxp-[a-zA-Z0-9-]+"
        r"|xoxb-[a-zA-Z0-9-]+"
        r"|ghp_[a-zA-Z0-9]{36}"
        r"|gho_[a-zA-Z0-9]{36}"
        r"|glpat-[a-zA-Z0-9_-]{20,}"
        r"|AKIA[0-9A-Z]{16}"
        r")\b"
    ),
}


class PIIDetector:
    """Configurable PII/secret scanner."""

    def __init__(self, config: PIIConfig):
        self.config = config
        self.patterns: dict[str, re.Pattern[str]] = {}

        for cat in config.categories:
            if cat in _BUILTIN_PATTERNS:
                self.patterns[cat] = _BUILTIN_PATTERNS[cat]

        for name, regex_str in config.custom_patterns.items():
            self.patterns[name] = re.compile(regex_str)

    def scan(self, text: str) -> list[tuple[str, str]]:
        """Return list of (category, matched_value) for all PII found."""
        findings: list[tuple[str, str]] = []
        for cat, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                findings.append((cat, match.group()))
        return findings

    def redact(self, text: str) -> str:
        """Replace all PII matches with the configured redaction string."""
        result = text
        for _cat, pattern in self.patterns.items():
            result = pattern.sub(self.config.redaction_string, result)
        return result


def _deep_redact(obj: Any, detector: PIIDetector) -> Any:
    """Recursively walk a JSON-like structure and redact PII in strings."""
    if isinstance(obj, str):
        return detector.redact(obj)
    if isinstance(obj, dict):
        return {k: _deep_redact(v, detector) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_redact(item, detector) for item in obj]
    return obj


def _deep_scan(obj: Any, detector: PIIDetector) -> list[tuple[str, str]]:
    """Recursively scan a JSON-like structure for PII."""
    findings: list[tuple[str, str]] = []
    if isinstance(obj, str):
        findings.extend(detector.scan(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            findings.extend(_deep_scan(v, detector))
    elif isinstance(obj, list):
        for item in obj:
            findings.extend(_deep_scan(item, detector))
    return findings


class PIIRule(PolicyRule):
    def __init__(self, config: PIIConfig):
        self.config = config
        self.detector = PIIDetector(config)

    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        """Scan outbound tool-call arguments for PII and redact if found."""
        findings = _deep_scan(ctx.arguments, self.detector)
        if not findings:
            return PolicyResult(decision=Decision.ALLOW)

        categories = sorted({cat for cat, _ in findings})
        reason = f"PII detected in request arguments ({', '.join(categories)})"
        logger.info(reason)

        redacted_args = _deep_redact(copy.deepcopy(ctx.arguments), self.detector)
        return PolicyResult(
            decision=Decision.SANITIZE,
            reason=reason,
            modifications={"arguments": redacted_args},
        )

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        """Scan inbound response content for PII and redact if found."""
        findings = _deep_scan(ctx.result, self.detector)
        if not findings:
            return PolicyResult(decision=Decision.ALLOW)

        categories = sorted({cat for cat, _ in findings})
        reason = f"PII detected in response ({', '.join(categories)})"
        logger.info(reason)

        redacted_result = _deep_redact(copy.deepcopy(ctx.result), self.detector)
        return PolicyResult(
            decision=Decision.SANITIZE,
            reason=reason,
            modifications={"result": redacted_result},
        )
