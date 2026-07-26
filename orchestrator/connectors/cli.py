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


async def run_cli(
    args: list[str],
    *,
    timeout: int,
    cwd: str | Path | None = None,
) -> CLIResult:
    """Run a fixed argv list without a shell to prevent command injection."""
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
            process.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise TimeoutError(f"Command timed out after {timeout}s: {args[0]}")

    return CLIResult(
        args=args,
        returncode=process.returncode or 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
