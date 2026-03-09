# MCP Firewall Gateway

An authorization proxy that sits between an AI client and upstream MCP (Model Context Protocol) servers. It intercepts JSON-RPC traffic and enforces security policies to prevent prompt injection, destructive shell command execution, and sensitive PII exfiltration.

## Architecture

```
AI Client  <──stdio──>  Gateway (this project)  <──stdio──>  Upstream MCP Server
                              │
                        ┌─────┴─────┐
                        │  Policy   │
                        │  Engine   │
                        ├───────────┤
                        │ Prompt    │
                        │ Injection │
                        ├───────────┤
                        │ Shell     │
                        │ Safety    │
                        ├───────────┤
                        │ PII       │
                        │ Detection │
                        └───────────┘
```

The gateway presents itself as a standard MCP server (over stdio) to the AI client while spawning the real upstream MCP server as a child process. Every request and response passes through a configurable policy engine.

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the gateway in front of any MCP server
python -m gateway.app.main -- <upstream-mcp-command>

# Example: wrap the filesystem MCP server
python -m gateway.app.main -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Configuration

Copy and edit `gateway/config.yaml`, or point to a custom file:

```bash
python -m gateway.app.main --config my_config.yaml -- <upstream-command>
```

Environment variable overrides:

| Variable | Description |
|---|---|
| `MCP_UPSTREAM_COMMAND` | Space-separated upstream MCP server command |
| `MCP_FAIL_OPEN` | Set to `true` to allow requests on policy engine errors |
| `MCP_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## Security policies

### Prompt injection detection

Heuristic scoring system that detects common injection patterns:

- Instruction-override attempts ("ignore previous instructions")
- System-prompt extraction probes
- Role reassignment / jailbreak attempts (DAN, developer mode)
- Special token injection (`<|im_start|>`, `[INST]`)
- Data exfiltration intent

Configurable threshold and hard/soft enforcement mode.

### Shell command safety

Blocks dangerous shell operations when tools execute commands:

- Destructive filesystem ops (`rm -rf`, `mkfs`, `dd`, `format`)
- System control (`shutdown`, `reboot`, `kill`)
- Remote code execution (`curl | bash`, `wget | sh`)
- Subshell/backtick expansion
- Compound commands with dangerous segments

### PII / secret detection

Scans both requests and responses for sensitive data:

- Email addresses, phone numbers, SSNs
- Credit card numbers
- API tokens (OpenAI, GitHub, GitLab, Slack, AWS)
- Custom regex patterns via configuration

Detected PII is automatically redacted before forwarding.

## Policy decisions

Each policy rule returns one of:

| Decision | Behavior |
|---|---|
| **ALLOW** | Forward message unchanged |
| **DENY** | Block and return a JSON-RPC error to the client |
| **SANITIZE** | Redact sensitive content and forward the modified message |

Rules are evaluated in pipeline order. A DENY from any rule short-circuits immediately.

## Testing

```bash
pip install -r requirements.txt
python -m pytest -v
```

68 tests covering:
- Policy engine orchestration (fail-closed/open, pipeline ordering)
- Prompt injection detection (14 test cases)
- Shell command safety (20 test cases)
- PII detection and redaction (14 test cases)
- Proxy integration (request forwarding, denial, sanitization, notifications)
- Configuration loading and env overrides

## Project layout

```
gateway/
├── config.yaml                     # Default configuration
├── app/
│   ├── main.py                     # Entrypoint
│   ├── proxy.py                    # Bidirectional MCP proxy
│   ├── mcp_transport.py            # Async stdio JSON-RPC transport
│   ├── config.py                   # Configuration models and loading
│   ├── logging_middleware.py        # Structured audit logging with redaction
│   └── policy/
│       ├── engine.py               # Policy engine, rule interface, decisions
│       ├── rules_prompt_injection.py
│       ├── rules_shell.py
│       └── rules_pii.py
└── tests/
    ├── test_engine.py
    ├── test_prompt_injection.py
    ├── test_shell.py
    ├── test_pii.py
    ├── test_proxy.py
    └── test_config.py
```

## Using with Cursor

Add to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "python",
      "args": [
        "-m", "gateway.app.main",
        "--config", "gateway/config.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/your/path"
      ]
    }
  }
}
```
