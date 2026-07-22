"""Holehe connector for public service-registration signals."""

from __future__ import annotations

import re
import shutil
import time

from config import settings
from intelligence.models import (
    ConnectorResult,
    Evidence,
    IdentityStatus,
    SourceReliability,
)

from .base import BaseConnector
from .cli import run_cli

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_POSITIVE = re.compile(r"^\[\+\]\s+([^\s]+)")


class HoleheConnector(BaseConnector):
    name = "holehe"
    identifier_type = "email"

    async def search(self, identifier: str) -> ConnectorResult:
        started = time.monotonic()
        email = identifier.strip().lower()
        if not _EMAIL.fullmatch(email):
            return ConnectorResult(
                connector=self.name,
                errors=["Invalid email address"],
            )

        binary = shutil.which("holehe")
        if not binary:
            return ConnectorResult(
                connector=self.name,
                errors=["Holehe is not installed or not on PATH"],
            )

        try:
            command_result = await run_cli(
                [binary, email, "--only-used", "--no-color"],
                timeout=max(settings.connector_timeout * 5, 90),
            )
        except TimeoutError as exc:
            return ConnectorResult(connector=self.name, errors=[str(exc)])

        evidence: list[Evidence] = []
        seen: set[str] = set()
        for raw_line in command_result.stdout.splitlines():
            line = _ANSI.sub("", raw_line).strip()
            match = _POSITIVE.match(line)
            if not match:
                continue
            service = match.group(1).strip("[](),:;").lower()
            if not service or service in seen:
                continue
            seen.add(service)
            evidence.append(
                Evidence(
                    type="service_registration",
                    value=service,
                    source=self.name,
                    confidence=0.62,
                    reliability=SourceReliability.MEDIUM,
                    identity_status=IdentityStatus.POSSIBLE,
                    notes=[
                        "Registration signals can contain false positives.",
                        "No password-reset action or account access was performed.",
                    ],
                    metadata={"email": email, "service": service},
                )
            )

        errors: list[str] = []
        if command_result.returncode != 0:
            errors.append(command_result.stderr.strip()[:500])

        return ConnectorResult(
            connector=self.name,
            evidence=evidence,
            errors=errors,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
