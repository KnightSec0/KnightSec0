"""Maigret username connector with conservative profile parsing."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Iterator
from urllib.parse import urlsplit

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


def _walk_dicts(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk_dicts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_dicts(item)


def _is_claimed(record: dict[str, Any]) -> bool:
    if record.get("exists") is True:
        return True

    status: Any = (
        record.get("status")
        or record.get("status_msg")
        or record.get("message")
        or ""
    )
    if isinstance(status, dict):
        status = (
            status.get("status")
            or status.get("status_msg")
            or status.get("message")
            or ""
        )
    return str(status).strip().casefold() in {
        "claimed",
        "found",
        "taken",
        "exists",
    }


def _site_from_url(url: str) -> str:
    """Return a stable public hostname, never Maigret's nested site config."""
    hostname = (urlsplit(url).hostname or "").strip(".").casefold()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname or "unknown"


def _site_name(record: dict[str, Any]) -> str | None:
    """Extract only a short scalar display name from a Maigret result."""
    candidates: list[Any] = [record.get("site_name"), record.get("name")]
    status = record.get("status")
    if isinstance(status, dict):
        candidates.extend([status.get("site_name"), status.get("name")])

    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        cleaned = " ".join(candidate.split()).strip()
        if cleaned and len(cleaned) <= 120:
            return cleaned
    return None


class MaigretConnector(BaseConnector):
    name = "maigret"
    identifier_type = "username"

    async def search(self, identifier: str) -> ConnectorResult:
        started = time.monotonic()
        if not _USERNAME.fullmatch(identifier):
            return ConnectorResult(
                connector=self.name,
                errors=["Username contains unsupported characters"],
            )

        binary = shutil.which("maigret")
        if not binary:
            return ConnectorResult(
                connector=self.name,
                errors=["Maigret is not installed or not on PATH"],
            )

        with tempfile.TemporaryDirectory(prefix="deepvault-maigret-") as temp_dir:
            try:
                command_result = await run_cli(
                    [
                        binary,
                        identifier,
                        "--json",
                        "simple",
                        "--folderoutput",
                        temp_dir,
                        "--no-color",
                        "--no-progressbar",
                        "--no-recursion",
                        "--no-extracting",
                        "--no-autoupdate",
                        "--timeout",
                        str(min(settings.connector_timeout, 60)),
                    ],
                    timeout=max(settings.connector_timeout * 8, 150),
                )
            except TimeoutError as exc:
                return ConnectorResult(connector=self.name, errors=[str(exc)])

            payloads: list[Any] = []
            for json_path in Path(temp_dir).glob("*.json"):
                try:
                    payloads.append(json.loads(json_path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue

        dedupe: set[str] = set()
        evidence: list[Evidence] = []
        for payload in payloads:
            for record in _walk_dicts(payload):
                if not _is_claimed(record):
                    continue
                url = (
                    record.get("url_user")
                    or record.get("url")
                    or record.get("profile_url")
                )
                if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                    continue
                if url in dedupe:
                    continue
                dedupe.add(url)
                metadata = {
                    "username": identifier,
                    "site": _site_from_url(url),
                }
                if display_name := _site_name(record):
                    metadata["site_name"] = display_name
                evidence.append(
                    Evidence(
                        type="social_profile",
                        value=url,
                        source=self.name,
                        source_url=url,
                        confidence=0.58,
                        reliability=SourceReliability.MEDIUM,
                        identity_status=IdentityStatus.POSSIBLE,
                        notes=[
                            "Username presence must be corroborated with profile attributes.",
                        ],
                        metadata=metadata,
                    )
                )

        errors: list[str] = []
        if command_result.returncode != 0:
            errors.append(command_result.stderr.strip()[:500])
        if not payloads and not errors:
            errors.append("Maigret produced no JSON report")

        return ConnectorResult(
            connector=self.name,
            evidence=evidence,
            errors=errors,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
