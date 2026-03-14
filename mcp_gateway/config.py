"""
Configuration loading for the MCP gateway.

Reads a YAML config file and merges with environment variable overrides.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


class ShellPolicyConfig(BaseModel):
    enabled: bool = True
    allowed_commands: list[str] = Field(
        default_factory=lambda: [
            "ls", "dir", "cat", "head", "tail", "echo", "pwd",
            "git status", "git log", "git diff", "git branch",
            "python --version", "pip list", "whoami", "date",
        ]
    )
    blocked_patterns: list[str] = Field(
        default_factory=lambda: [
            r"rm\s+(-\w+\s+)*-r",
            r"rm\s+(-\w+\s+)*-f",
            r"mkfs",
            r"dd\s+.*of=/dev/",
            r">\s*/dev/sd",
            r"chmod\s+777",
            r"curl\s+.*\|\s*(ba)?sh",
            r"wget\s+.*\|\s*(ba)?sh",
            r"nc\s+-l",
            r"ncat\s+-l",
            r"shutdown",
            r"reboot",
            r"format\s+[a-zA-Z]:",
        ]
    )
    blocked_commands: list[str] = Field(
        default_factory=lambda: [
            "rm", "rmdir", "del", "format",
            "mkfs", "dd", "fdisk",
            "shutdown", "reboot", "halt", "poweroff",
            "kill", "killall", "pkill",
            "net user", "net localgroup",
            "reg delete", "reg add",
        ]
    )


class PromptInjectionConfig(BaseModel):
    enabled: bool = True
    score_threshold: float = 0.6
    mode: str = "hard"  # "hard" = deny, "soft" = log-only


class PIIConfig(BaseModel):
    enabled: bool = True
    categories: list[str] = Field(
        default_factory=lambda: [
            "email", "phone", "ssn", "credit_card", "api_token",
        ]
    )
    custom_patterns: dict[str, str] = Field(default_factory=dict)
    redaction_string: str = "***REDACTED***"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    redact_in_logs: bool = True
    log_file: str | None = None


class UpstreamConfig(BaseModel):
    command: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class GatewayConfig(BaseModel):
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    shell_policy: ShellPolicyConfig = Field(default_factory=ShellPolicyConfig)
    prompt_injection: PromptInjectionConfig = Field(default_factory=PromptInjectionConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    fail_closed: bool = True


def load_config(path: str | Path | None = None) -> GatewayConfig:
    """Load gateway configuration from YAML, with env-var overrides."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw: dict[str, Any] = {}

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

    if env_cmd := os.environ.get("MCP_UPSTREAM_COMMAND"):
        raw.setdefault("upstream", {})["command"] = env_cmd.split()

    if os.environ.get("MCP_FAIL_OPEN", "").lower() in ("1", "true", "yes"):
        raw["fail_closed"] = False

    if log_level := os.environ.get("MCP_LOG_LEVEL"):
        raw.setdefault("logging", {})["level"] = log_level.upper()

    return GatewayConfig(**raw)
