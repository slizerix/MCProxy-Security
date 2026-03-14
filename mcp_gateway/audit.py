"""
Structured audit logging with optional PII redaction.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

from mcp_gateway.config import LoggingConfig

logger = logging.getLogger("mcp_gateway.audit")

_LOG_REDACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("api_token", re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|xoxp-[a-zA-Z0-9-]+|ghp_[a-zA-Z0-9]{36})\b")),
]

REDACTED = "***REDACTED***"


def _redact(text: str) -> str:
    for _name, pattern in _LOG_REDACTION_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def configure_logging(cfg: LoggingConfig) -> None:
    """Set up Python logging for the whole gateway process."""
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if cfg.log_file:
        handlers.append(logging.FileHandler(cfg.log_file, encoding="utf-8"))

    level = getattr(logging, cfg.level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


def audit_log(
    *,
    event: str,
    decision: str,
    reason: str = "",
    method: str = "",
    tool_name: str = "",
    extra: dict[str, Any] | None = None,
    redact: bool = True,
) -> None:
    """Write a structured audit record."""
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "decision": decision,
        "method": method,
        "tool_name": tool_name,
        "reason": reason,
    }
    if extra:
        record["extra"] = extra

    line = json.dumps(record, default=str)
    if redact:
        line = _redact(line)

    logger.info(line)
