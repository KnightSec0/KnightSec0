"""Safe subprocess execution for local OSINT tools."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import time


@dataclass(slots=True)
class CLIResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


class CLIOutputLimitExceeded(RuntimeError):
    """Raised when a child process exceeds the bounded capture budget."""


async def _read_bounded(
    stream: asyncio.StreamReader,
    *,
    limit: int,
) -> bytes:
    output = bytearray()
    while True:
        chunk = await stream.read(min(65536, limit + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > limit:
            raise CLIOutputLimitExceeded(
                f"Command output exceeded the configured {limit}-byte limit"
            )


async def _collect_bounded(
    process: asyncio.subprocess.Process,
    *,
    max_output_bytes: int,
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("Subprocess output pipes were not created")
    tasks = [
        asyncio.create_task(
            _read_bounded(process.stdout, limit=max_output_bytes)
        ),
        asyncio.create_task(
            _read_bounded(process.stderr, limit=max_output_bytes)
        ),
    ]
    try:
        stdout_bytes, stderr_bytes = await asyncio.gather(*tasks)
        await process.wait()
        return stdout_bytes, stderr_bytes
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def run_cli(
    args: list[str],
    *,
    timeout: int,
    cwd: str | Path | None = None,
    max_output_bytes: int = 5 * 1024 * 1024,
) -> CLIResult:
    """Run a fixed argv list without a shell to prevent command injection."""
    if not args:
        raise ValueError("Command argument list cannot be empty")
    if timeout < 1 or max_output_bytes < 1:
        raise ValueError("Command timeout and output limit must be positive")
    started = time.monotonic()
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    process = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd) if cwd else None,
        env=environment,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            _collect_bounded(
                process,
                max_output_bytes=max_output_bytes,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise TimeoutError(f"Command timed out after {timeout}s: {args[0]}")

    return CLIResult(
        args=args,
        returncode=process.returncode or 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
