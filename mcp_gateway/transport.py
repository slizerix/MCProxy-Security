"""
Async JSON-RPC / MCP transport layer.

Supports stdio-based communication with both the downstream client (via
this process's own stdin/stdout) and an upstream MCP server spawned as a
child process.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)

ENCODING = "utf-8"


class StdioTransport:
    """Read/write newline-delimited JSON-RPC messages over a pair of streams."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        label: str = "transport",
    ):
        self.reader = reader
        self.writer = writer
        self.label = label

    async def read_message(self) -> dict[str, Any] | None:
        """Read one JSON-RPC message. Returns *None* on EOF."""
        while True:
            raw = await self.reader.readline()
            if not raw:
                return None
            line = raw.decode(ENCODING).strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                logger.debug("[%s] recv: %s", self.label, line[:256])
                return msg
            except json.JSONDecodeError as exc:
                logger.warning("[%s] malformed JSON, skipping: %s", self.label, exc)
                continue

    async def write_message(self, msg: dict[str, Any]) -> None:
        """Write one JSON-RPC message followed by a newline."""
        line = json.dumps(msg, separators=(",", ":"))
        self.writer.write((line + "\n").encode(ENCODING))
        await self.writer.drain()
        logger.debug("[%s] sent: %s", self.label, line[:256])


async def open_client_transport() -> StdioTransport:
    """Create a transport connected to this process's own stdin/stdout.

    This is the *downstream* side — the AI client talks to us here.
    """
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    w_transport, w_protocol = await loop.connect_write_pipe(
        lambda: asyncio.streams.FlowControlMixin(), sys.stdout.buffer
    )
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
    return StdioTransport(reader, writer, label="client")


async def open_upstream_transport(
    command: list[str],
    env: dict[str, str] | None = None,
) -> tuple[StdioTransport, asyncio.subprocess.Process]:
    """Spawn the upstream MCP server and wrap its stdio as a transport."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    assert process.stdin is not None
    assert process.stdout is not None

    reader = process.stdout
    writer_transport = process.stdin

    sr = asyncio.StreamReader()

    async def _pipe_reader():
        while True:
            data = await reader.read(8192)
            if not data:
                sr.feed_eof()
                break
            sr.feed_data(data)

    asyncio.ensure_future(_pipe_reader())

    class _SubprocWriter:
        """Minimal shim so StdioTransport can use process.stdin."""

        def write(self, data: bytes) -> None:
            writer_transport.write(data)

        async def drain(self) -> None:
            await writer_transport.drain()

    transport = StdioTransport(
        reader=sr,
        writer=_SubprocWriter(),  # type: ignore[arg-type]
        label="upstream",
    )
    return transport, process
