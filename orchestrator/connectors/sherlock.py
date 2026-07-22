"""Sherlock username connector using its documented JSON export."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any

from config import settings
from intelligence.models import (
    ConnectorResult,
    Evidence,
    IdentityStatus,
    SourceReliability,
)

from .base import BaseConnector
from .cli import run_cli

_USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _claimed(details: dict[str, Any]) -> bool:
    if details.get("exists") is True:
        return True
    status = str(details.get("status", "")).casefold()
    return any(word in status for word in ("claimed", "found", "taken", "exists"))


class SherlockConnector(BaseConnector):
    name = "sherlock"
    identifier_type = "username"

    async def search(self, identifier: str) -> ConnectorResult:
        started = time.monotonic()
        if not _USERNAME.fullmatch(identifier):
            return ConnectorResult(
                connector=self.name,
                errors=["Username contains unsupported characters"],
            )

        binary = shutil.which("sherlock")
        if not binary:
            return ConnectorResult(
                connector=self.name,
                errors=["Sherlock is not installed or not on PATH"],
            )

        with tempfile.TemporaryDirectory(prefix="deepvault-sherlock-") as temp_dir:
            output_path = Path(temp_dir) / "result.json"
            try:
                command_result = await run_cli(
                    [
                        binary,
                        identifier,
                        "--json",
                        str(output_path),
                        "--print-found",
                        "--no-color",
                        "--timeout",
                        str(min(settings.connector_timeout, 60)),
                    ],
                    timeout=max(settings.connector_timeout * 5, 90),
                )
            except TimeoutError as exc:
                return ConnectorResult(connector=self.name, errors=[str(exc)])

            if not output_path.exists():
                error = command_result.stderr.strip() or "Sherlock produced no JSON output"
                return ConnectorResult(
                    connector=self.name,
                    errors=[error[:500]],
                    duration_ms=command_result.duration_ms,
                )

            try:
                payload = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return ConnectorResult(
                    connector=self.name,
                    errors=[f"Invalid Sherlock JSON: {exc}"],
                    duration_ms=command_result.duration_ms,
                )

        evidence: list[Evidence] = []
        if isinstance(payload, dict):
            for site, details in payload.items():
                if not isinstance(details, dict) or not _claimed(details):
                    continue
                url = (
                    details.get("url_user")
                    or details.get("url")
                    or details.get("url_main")
                )
                if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                    continue
                evidence.append(
                    Evidence(
                        type="social_profile",
                        value=url,
                        source=self.name,
                        source_url=url,
                        confidence=0.55,
                        reliability=SourceReliability.MEDIUM,
                        identity_status=IdentityStatus.POSSIBLE,
                        notes=[
                            "Username presence is not sufficient to confirm identity.",
                            "Manual profile-content validation is required.",
                        ],
                        metadata={
                            "username": identifier,
                            "site": str(site),
                            "status": str(details.get("status", "claimed")),
                        },
                    )
                )

        return ConnectorResult(
            connector=self.name,
            evidence=evidence,
            errors=(
                []
                if command_result.returncode == 0
                else [command_result.stderr.strip()[:500]]
            ),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
