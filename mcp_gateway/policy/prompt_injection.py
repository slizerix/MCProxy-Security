"""
Prompt-injection detection policy.

Uses a scoring-based heuristic system: each suspicious pattern contributes a
score, and the total is compared against a configurable threshold.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from mcp_gateway.config import PromptInjectionConfig
from mcp_gateway.policy.engine import Decision, PolicyResult, PolicyRule, RequestContext, ResponseContext

logger = logging.getLogger(__name__)

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)", re.I), 0.9,
     "instruction override attempt"),
    (re.compile(r"disregard\s+(all\s+)?(your\s+)?(previous|prior|above)?\s*(instructions|rules|directives|guidelines)", re.I), 0.9,
     "instruction override attempt"),
    (re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules)", re.I), 0.85,
     "memory wipe attempt"),
    (re.compile(r"you\s+are\s+now\s+(a|an|in)\b", re.I), 0.7,
     "role reassignment attempt"),
    (re.compile(r"new\s+(role|persona|identity|instructions)\s*:", re.I), 0.75,
     "role reassignment attempt"),

    (re.compile(r"(print|show|reveal|repeat|output)\s+(your\s+)?(system\s+prompt|instructions|rules)", re.I), 0.8,
     "system prompt extraction"),
    (re.compile(r"what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions|prompt|rules)", re.I), 0.75,
     "system prompt probing"),

    (re.compile(r"(exfiltrate|steal|extract|send)\s+.*\b(data|secrets?|tokens?|keys?|credentials?|passwords?)\b", re.I), 0.9,
     "data exfiltration intent"),
    (re.compile(r"(encode|base64|hex)\s+(and\s+)?(send|transmit|post|upload)\b", re.I), 0.7,
     "encoded exfiltration attempt"),

    (re.compile(r"<\|?(system|im_start|im_end|endoftext)\|?>", re.I), 0.85,
     "special token injection"),
    (re.compile(r"\[INST\]|\[/INST\]|\[SYS\]", re.I), 0.85,
     "instruction tag injection"),

    (re.compile(r"---+\s*(begin|start|new)\s*(prompt|instruction|system)", re.I), 0.7,
     "delimiter injection"),
    (re.compile(r"#{3,}\s*(system|admin|root)\s*(prompt|message|instructions?)", re.I), 0.7,
     "markdown header injection"),

    (re.compile(r"\bDAN\b.*\b(mode|jailbreak|persona)\b", re.I), 0.8,
     "DAN-style jailbreak"),
    (re.compile(r"(developer|debug|admin|sudo|god)\s*mode", re.I), 0.75,
     "privilege escalation attempt"),
]


def _score_text(text: str) -> list[tuple[float, str]]:
    """Return a list of (score, description) for all matched patterns."""
    hits: list[tuple[float, str]] = []
    for pattern, weight, desc in _INJECTION_PATTERNS:
        if pattern.search(text):
            hits.append((weight, desc))
    return hits


def _extract_text_from_arguments(arguments: dict[str, Any]) -> str:
    """Recursively extract string values from tool arguments for scanning."""
    parts: list[str] = []
    for v in arguments.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(_extract_text_from_arguments(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(_extract_text_from_arguments(item))
    return " ".join(parts)


class PromptInjectionRule(PolicyRule):
    def __init__(self, config: PromptInjectionConfig):
        self.config = config

    def evaluate_request(self, ctx: RequestContext) -> PolicyResult:
        text_to_scan = _extract_text_from_arguments(ctx.arguments)
        if not text_to_scan.strip():
            text_to_scan = _extract_text_from_arguments(ctx.params)

        hits = _score_text(text_to_scan)
        if not hits:
            return PolicyResult(decision=Decision.ALLOW)

        total = min(sum(s for s, _ in hits), 1.0)
        descriptions = "; ".join(desc for _, desc in hits)
        reason = f"Prompt injection detected (score={total:.2f}): {descriptions}"

        if total >= self.config.score_threshold:
            if self.config.mode == "hard":
                return PolicyResult(decision=Decision.DENY, reason=reason, score=total)
            else:
                logger.warning("[soft-mode] %s", reason)
                return PolicyResult(decision=Decision.ALLOW, reason=reason, score=total)

        return PolicyResult(decision=Decision.ALLOW, score=total)

    def evaluate_response(self, ctx: ResponseContext) -> PolicyResult:
        return PolicyResult(decision=Decision.ALLOW)
