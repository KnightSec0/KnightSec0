"""Sherlock username connector using its supported CSV export."""

from __future__ import annotations

import csv
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any
from urllib.parse import unquote, urlsplit

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
    status = details.get("exists") or details.get("status") or ""
    status_token = str(status).strip().casefold().rsplit(".", 1)[-1]
    return status_token in {
        "claimed",
        "found",
        "taken",
        "exists",
    }


def _site_from_url(url: str) -> str:
    hostname = (urlsplit(url).hostname or "").strip(".").casefold()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname or "unknown"


def _http_status(details: dict[str, Any]) -> int | None:
    for key in ("http_status", "status_code", "httpStatus"):
        value = details.get(key)
        if isinstance(value, int) and 100 <= value <= 599:
            return value
        if isinstance(value, str):
            match = re.search(r"\b([1-5][0-9]{2})\b", value)
            if match:
                return int(match.group(1))
    return None


def _username_profile_url(url: str, username: str) -> bool:
    """Reject home/search URLs that cannot identify the queried account."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    searchable = unquote(f"{parsed.path}?{parsed.query}").casefold()
    token = username.casefold()
    return bool(
        re.search(rf"(?<![\w.-]){re.escape(token)}(?![\w.-])", searchable)
    )


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
            try:
                command_result = await run_cli(
                    [
                        binary,
                        identifier,
                        "--csv",
                        "--folderoutput",
                        temp_dir,
                        "--no-txt",
                        "--print-found",
                        "--no-color",
                        "--local",
                        "--timeout",
                        str(min(settings.connector_timeout, 60)),
                    ],
                    timeout=max(settings.connector_timeout * 5, 90),
                )
            except TimeoutError as exc:
                return ConnectorResult(connector=self.name, errors=[str(exc)])

            csv_paths = sorted(Path(temp_dir).glob("*.csv"))
            if not csv_paths:
                error = command_result.stderr.strip() or "Sherlock produced no CSV report"
                return ConnectorResult(
                    connector=self.name,
                    errors=[error[:500]],
                    duration_ms=command_result.duration_ms,
                )

            try:
                with csv_paths[0].open(
                    "r",
                    encoding="utf-8",
                    newline="",
                ) as report_file:
                    payload = list(csv.DictReader(report_file))
            except (OSError, csv.Error) as exc:
                return ConnectorResult(
                    connector=self.name,
                    errors=[f"Invalid Sherlock CSV: {exc}"],
                    duration_ms=command_result.duration_ms,
                )

        evidence: list[Evidence] = []
        seen: set[str] = set()
        for details in payload:
            if not _claimed(details):
                continue
            url = details.get("url_user")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            if not _username_profile_url(url, identifier):
                continue
            if url in seen:
                continue
            seen.add(url)
            site = str(details.get("name") or "").strip()[:120]
            status_code = _http_status(details)
            metadata: dict[str, Any] = {
                "username": identifier,
                "site": site or _site_from_url(url),
                "platform": _site_from_url(url),
                "status": str(
                    details.get("exists")
                    or details.get("status")
                    or "claimed"
                ),
                "catalogue_claimed": True,
            }
            if status_code is not None:
                metadata["http_status"] = status_code
                metadata["profile_accessible"] = status_code < 400
                if status_code in {404, 410}:
                    metadata["profile_exists"] = False
                    metadata["not_found"] = True
                elif status_code >= 400:
                    metadata["inaccessible_profile"] = True
            evidence.append(
                Evidence(
                    type="social_profile",
                    value=url,
                    source=self.name,
                    source_url=url,
                    confidence=0.55,
                    reliability=SourceReliability.MEDIUM,
                    identity_status=IdentityStatus.POSSIBLE,
                    independence_group="sherlock-catalog",
                    notes=[
                        "Username presence is not sufficient to confirm identity.",
                        "Manual profile-content validation is required.",
                    ],
                    metadata=metadata,
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
