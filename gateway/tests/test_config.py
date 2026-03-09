"""Tests for configuration loading."""

import tempfile
from pathlib import Path

import yaml

from gateway.app.config import GatewayConfig, load_config


class TestConfigLoading:
    def test_default_config(self):
        cfg = GatewayConfig()
        assert cfg.fail_closed is True
        assert cfg.shell_policy.enabled is True
        assert cfg.prompt_injection.enabled is True
        assert cfg.pii.enabled is True

    def test_load_from_yaml(self, tmp_path: Path):
        data = {
            "fail_closed": False,
            "shell_policy": {"enabled": False},
            "prompt_injection": {"score_threshold": 0.8, "mode": "soft"},
            "pii": {"categories": ["email"]},
            "upstream": {"command": ["echo", "hello"]},
        }
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(yaml.dump(data))

        cfg = load_config(config_file)
        assert cfg.fail_closed is False
        assert cfg.shell_policy.enabled is False
        assert cfg.prompt_injection.score_threshold == 0.8
        assert cfg.prompt_injection.mode == "soft"
        assert cfg.pii.categories == ["email"]
        assert cfg.upstream.command == ["echo", "hello"]

    def test_load_nonexistent_uses_defaults(self, tmp_path: Path):
        cfg = load_config(tmp_path / "does_not_exist.yaml")
        assert cfg.fail_closed is True

    def test_env_overrides(self, monkeypatch, tmp_path: Path):
        config_file = tmp_path / "cfg.yaml"
        config_file.write_text("{}")

        monkeypatch.setenv("MCP_UPSTREAM_COMMAND", "python -m my_server")
        monkeypatch.setenv("MCP_FAIL_OPEN", "true")
        monkeypatch.setenv("MCP_LOG_LEVEL", "debug")

        cfg = load_config(config_file)
        assert cfg.upstream.command == ["python", "-m", "my_server"]
        assert cfg.fail_closed is False
        assert cfg.logging.level == "DEBUG"

    def test_shell_policy_defaults(self):
        cfg = GatewayConfig()
        assert "rm" in cfg.shell_policy.blocked_commands
        assert "ls" in cfg.shell_policy.allowed_commands

    def test_pii_defaults(self):
        cfg = GatewayConfig()
        assert "email" in cfg.pii.categories
        assert "ssn" in cfg.pii.categories
        assert cfg.pii.redaction_string == "***REDACTED***"
