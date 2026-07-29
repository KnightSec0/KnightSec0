"""Passive enrichment from an authorized email's public Gravatar profile."""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from config import settings
from intelligence.models import (
    ConnectorResult,
    Evidence,
    IdentityStatus,
    SourceReliability,
)

from .base import BaseConnector

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_STRING_FIELDS = (
    "display_name",
    "preferred_username",
    "first_name",
    "last_name",
    "description",
    "location",
    "job_title",
    "company",
    "pronunciation",
    "pronouns",
    "timezone",
)
_URL_FIELDS = ("profile_url",)
_MAX_PUBLIC_VALUE_LENGTH = 4000


def _public_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned[:_MAX_PUBLIC_VALUE_LENGTH]


def _public_http_url(value: Any) -> str | None:
    cleaned = _public_string(value)
    if cleaned is None:
        return None
    parsed = urlsplit(cleaned)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        return None
    return cleaned


def _is_hidden(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes"}
    return bool(value)


def _contains_forbidden(value: str, forbidden_values: tuple[str, ...]) -> bool:
    candidate = value.casefold()
    return any(
        forbidden and forbidden.casefold() in candidate
        for forbidden in forbidden_values
    )


def _visible_verified_accounts(
    value: Any,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []

    accounts: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or _is_hidden(item.get("is_hidden")):
            continue
        url = _public_http_url(item.get("url"))
        if (
            url is None
            or url in seen_urls
            or _contains_forbidden(url, forbidden_values)
        ):
            continue
        account = {"url": url}
        label = _public_string(item.get("service_label") or item.get("label"))
        account_type = _public_string(item.get("service_type") or item.get("type"))
        if label is not None and not _contains_forbidden(label, forbidden_values):
            account["label"] = label
        if account_type is not None and not _contains_forbidden(
            account_type, forbidden_values
        ):
            account["type"] = account_type
        accounts.append(account)
        seen_urls.add(url)
    return accounts


def _allowlisted_profile(
    raw_profile: Any,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Copy documented public fields without retaining email or hash identifiers."""
    if not isinstance(raw_profile, dict):
        return {}

    profile: dict[str, Any] = {}
    for field in _STRING_FIELDS:
        value = _public_string(raw_profile.get(field))
        if value is not None and not _contains_forbidden(value, forbidden_values):
            profile[field] = value
    for field in _URL_FIELDS:
        value = _public_http_url(raw_profile.get(field))
        if value is not None and not _contains_forbidden(value, forbidden_values):
            profile[field] = value

    languages = raw_profile.get("languages")
    if isinstance(languages, list):
        cleaned_languages = [
            cleaned
            for item in languages
            if (cleaned := _public_string(item)) is not None
            and not _contains_forbidden(cleaned, forbidden_values)
        ]
        if cleaned_languages:
            profile["languages"] = cleaned_languages

    verified_accounts = _visible_verified_accounts(
        raw_profile.get("verified_accounts"),
        forbidden_values=forbidden_values,
    )
    if verified_accounts:
        profile["verified_accounts"] = verified_accounts
    return profile


class GravatarProfileConnector(BaseConnector):
    """Read an existing public profile without account access or recovery actions."""

    name = "gravatar"
    identifier_type = "email"

    async def _get(
        self,
        url: str,
        *,
        headers: dict[str, str],
    ) -> httpx.Response:
        async with httpx.AsyncClient(timeout=settings.connector_timeout) as client:
            return await client.get(url, headers=headers)

    async def search(self, identifier: str) -> ConnectorResult:
        started = time.monotonic()
        email = identifier.strip().casefold()
        if not _EMAIL.fullmatch(email):
            return ConnectorResult(
                connector=self.name,
                errors=["Invalid email address"],
            )

        # The hash is required by Gravatar's public lookup API and deliberately
        # remains local to this request; it is never placed in evidence metadata.
        email_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
        headers = {
            "Accept": "application/json",
            "User-Agent": "SIGMA-WorldAtlas/2.0",
        }
        if settings.gravatar_api_key:
            headers["Authorization"] = f"Bearer {settings.gravatar_api_key}"

        response = await self._get(
            f"https://api.gravatar.com/v3/profiles/{email_hash}",
            headers=headers,
        )
        if response.status_code == 404:
            return ConnectorResult(
                connector=self.name,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        response.raise_for_status()

        public_profile = _allowlisted_profile(
            response.json(),
            forbidden_values=(email, email_hash),
        )
        if not public_profile:
            return ConnectorResult(
                connector=self.name,
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        profile_url = _public_http_url(public_profile.get("profile_url"))
        value = (
            profile_url
            or _public_string(public_profile.get("preferred_username"))
            or _public_string(public_profile.get("display_name"))
            or "Public Gravatar profile"
        )
        evidence = Evidence(
            type="public_profile",
            value=value,
            source=self.name,
            source_url=profile_url,
            confidence=0.64,
            reliability=SourceReliability.MEDIUM,
            identity_status=IdentityStatus.POSSIBLE,
            notes=[
                "The profile is publicly self-published and does not prove "
                "identity by itself.",
                "The authorized email hash was used only for the API request "
                "and was not persisted.",
                "Verify linked accounts independently before attribution.",
            ],
            metadata=public_profile,
        )
        return ConnectorResult(
            connector=self.name,
            evidence=[evidence],
            duration_ms=int((time.monotonic() - started) * 1000),
        )
