"""API-backed person intelligence connectors with normalized provenance."""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import ipaddress
import time
from typing import Any
from urllib.parse import quote

import httpx

from config import settings
from intelligence.models import (
    ConnectorResult,
    Evidence,
    IdentityStatus,
    SourceReliability,
)

from .base import BaseConnector


class HTTPConnector(BaseConnector):
    """Small shared client which never logs request headers or API credentials."""

    async def _get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        async with httpx.AsyncClient(timeout=settings.connector_timeout) as client:
            return await client.get(url, headers=headers, params=params)


class GitHubProfileConnector(HTTPConnector):
    name = "github"
    identifier_type = "username"

    async def search(self, identifier: str) -> ConnectorResult:
        started = time.monotonic()
        headers = {"Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        response = await self._get(
            f"https://api.github.com/users/{quote(identifier, safe='')}",
            headers=headers,
        )
        if response.status_code == 404:
            return ConnectorResult(connector=self.name)
        response.raise_for_status()
        profile = response.json()
        url = str(profile.get("html_url") or "")
        public_fields = {
            key: profile.get(key)
            for key in (
                "login",
                "name",
                "company",
                "blog",
                "location",
                "bio",
                "public_repos",
                "followers",
                "following",
                "created_at",
                "updated_at",
            )
        }
        evidence = Evidence(
            type="github_profile",
            value=url or identifier,
            source=self.name,
            source_url=url or None,
            confidence=0.62,
            reliability=SourceReliability.HIGH,
            identity_status=IdentityStatus.POSSIBLE,
            notes=["A username match alone does not establish identity."],
            metadata={"public_profile": public_fields},
        )
        return ConnectorResult(
            connector=self.name,
            evidence=[evidence],
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class HIBPConnector(HTTPConnector):
    """HIBP breach metadata only; never fetches or persists credential material."""

    name = "hibp"
    identifier_type = "email"

    async def search(self, identifier: str) -> ConnectorResult:
        if not settings.hibp_api_key:
            return ConnectorResult(
                connector=self.name, errors=["HIBP_API_KEY is not configured"]
            )
        response = await self._get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(identifier, safe='')}",
            headers={
                "hibp-api-key": settings.hibp_api_key,
                "user-agent": "DeepVault/2.0",
            },
            params={"truncateResponse": "false"},
        )
        if response.status_code == 404:
            return ConnectorResult(connector=self.name)
        response.raise_for_status()
        evidence = [
            Evidence(
                type="breach",
                value=str(item.get("Name") or "unnamed breach"),
                source=self.name,
                source_url="https://haveibeenpwned.com/",
                confidence=0.90,
                reliability=SourceReliability.HIGH,
                identity_status=IdentityStatus.PROBABLE,
                metadata={
                    "email": identifier,
                    "breach_name": item.get("Name"),
                    "breach_date": item.get("BreachDate"),
                    "added_date": item.get("AddedDate"),
                    "modified_date": item.get("ModifiedDate"),
                    "domain": item.get("Domain"),
                    "data_classes": item.get("DataClasses", []),
                    "verified": bool(item.get("IsVerified")),
                    "fabricated": bool(item.get("IsFabricated")),
                    "spam_list": bool(item.get("IsSpamList")),
                },
            )
            for item in response.json()
        ]
        return ConnectorResult(connector=self.name, evidence=evidence)


class HunterConnector(HTTPConnector):
    name = "hunter"
    identifier_type = "email"

    async def search(self, identifier: str) -> ConnectorResult:
        if not settings.hunter_api_key:
            return ConnectorResult(
                connector=self.name, errors=["HUNTER_API_KEY is not configured"]
            )
        response = await self._get(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": identifier, "api_key": settings.hunter_api_key},
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        evidence = Evidence(
            type="email_verification",
            value=identifier,
            source=self.name,
            confidence=min(max(float(data.get("score") or 0) / 100, 0.1), 0.9),
            reliability=SourceReliability.MEDIUM,
            identity_status=IdentityStatus.INSUFFICIENT_EVIDENCE,
            metadata={
                "status": data.get("status"),
                "result": data.get("result"),
                "score": data.get("score"),
                "regexp": data.get("regexp"),
                "gibberish": data.get("gibberish"),
                "disposable": data.get("disposable"),
                "webmail": data.get("webmail"),
                "mx_records": data.get("mx_records"),
                "smtp_server": data.get("smtp_server"),
                "accept_all": data.get("accept_all"),
                "block": data.get("block"),
            },
        )
        return ConnectorResult(connector=self.name, evidence=[evidence])


class BravePersonSearchConnector(HTTPConnector):
    name = "brave"
    identifier_type = "person_query"

    async def search(self, identifier: str) -> ConnectorResult:
        if not settings.brave_api_key:
            return ConnectorResult(
                connector=self.name, errors=["BRAVE_API_KEY is not configured"]
            )
        response = await self._get(
            "https://api.search.brave.com/res/v1/web/search",
            headers={"X-Subscription-Token": settings.brave_api_key},
            params={"q": identifier, "count": 20, "safesearch": "moderate"},
        )
        response.raise_for_status()
        evidence = []
        for item in response.json().get("web", {}).get("results", []):
            url = str(item.get("url") or "")
            if not url:
                continue
            evidence.append(
                Evidence(
                    type="person_search_result",
                    value=url,
                    source=self.name,
                    source_url=url,
                    confidence=0.35,
                    reliability=SourceReliability.MEDIUM,
                    identity_status=IdentityStatus.POSSIBLE,
                    notes=[
                        "Search results are candidates only.",
                        "Disambiguate with at least two target attributes before attribution.",
                    ],
                    metadata={
                        "query": identifier,
                        "title": item.get("title"),
                        "description": item.get("description"),
                        "disambiguation_required": True,
                    },
                )
            )
        return ConnectorResult(connector=self.name, evidence=evidence)


class SpiderFootConnector(HTTPConnector):
    """Submit a passive scan to an explicitly configured local SpiderFoot API."""

    name = "spiderfoot"
    identifier_type = "target"

    async def search(self, identifier: str) -> ConnectorResult:
        if not settings.spiderfoot_url:
            return ConnectorResult(
                connector=self.name, errors=["SPIDERFOOT_URL is not configured"]
            )
        async with httpx.AsyncClient(timeout=settings.connector_timeout) as client:
            response = await client.post(
                f"{settings.spiderfoot_url.rstrip('/')}/startscan",
                data={
                    "scanname": f"DeepVault passive {datetime.now(timezone.utc).isoformat()}",
                    "scantarget": identifier,
                    "usecase": "passive",
                },
            )
        response.raise_for_status()
        scan_id = response.text.strip().strip('"')
        return ConnectorResult(
            connector=self.name,
            evidence=[
                Evidence(
                    type="passive_scan",
                    value=scan_id,
                    source=self.name,
                    confidence=0.5,
                    reliability=SourceReliability.MEDIUM,
                    metadata={
                        "target": identifier,
                        "mode": "passive",
                        "status": "submitted",
                    },
                )
            ],
        )


def _authorized_ip(
    identifier: str,
    *,
    infrastructure_enrichment: bool,
    authorization_reference: str | None,
) -> str:
    if not infrastructure_enrichment:
        raise PermissionError("ALLOW_INFRASTRUCTURE_ENRICHMENT is not enabled")
    if not authorization_reference:
        raise PermissionError("AUTHORIZATION_REFERENCE is required")
    return str(ipaddress.ip_address(identifier))


class ShodanConnector(HTTPConnector):
    name = "shodan"
    identifier_type = "authorized_ip"

    def __init__(
        self,
        *,
        authorization_reference: str | None = None,
        infrastructure_enrichment: bool | None = None,
    ) -> None:
        self.authorization_reference = (
            authorization_reference or settings.authorization_reference
        )
        self.infrastructure_enrichment = (
            settings.allow_infrastructure_enrichment
            if infrastructure_enrichment is None
            else infrastructure_enrichment
        )

    async def search(self, identifier: str) -> ConnectorResult:
        ip = _authorized_ip(
            identifier,
            infrastructure_enrichment=self.infrastructure_enrichment,
            authorization_reference=self.authorization_reference,
        )
        if not settings.shodan_api_key:
            return ConnectorResult(
                connector=self.name, errors=["SHODAN_API_KEY is not configured"]
            )
        response = await self._get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": settings.shodan_api_key, "minify": "true"},
        )
        response.raise_for_status()
        data = response.json()
        return ConnectorResult(
            connector=self.name,
            evidence=[
                Evidence(
                    type="authorized_infrastructure",
                    value=ip,
                    source=self.name,
                    confidence=0.8,
                    reliability=SourceReliability.HIGH,
                    metadata={
                        "authorization_reference": self.authorization_reference,
                        "hostnames": data.get("hostnames", []),
                        "domains": data.get("domains", []),
                        "ports": data.get("ports", []),
                        "org": data.get("org"),
                        "asn": data.get("asn"),
                        "last_update": data.get("last_update"),
                    },
                )
            ],
        )


class CensysConnector(HTTPConnector):
    name = "censys"
    identifier_type = "authorized_ip"

    def __init__(
        self,
        *,
        authorization_reference: str | None = None,
        infrastructure_enrichment: bool | None = None,
    ) -> None:
        self.authorization_reference = (
            authorization_reference or settings.authorization_reference
        )
        self.infrastructure_enrichment = (
            settings.allow_infrastructure_enrichment
            if infrastructure_enrichment is None
            else infrastructure_enrichment
        )

    async def search(self, identifier: str) -> ConnectorResult:
        ip = _authorized_ip(
            identifier,
            infrastructure_enrichment=self.infrastructure_enrichment,
            authorization_reference=self.authorization_reference,
        )
        if not settings.censys_api_id or not settings.censys_api_secret:
            return ConnectorResult(
                connector=self.name, errors=["Censys credentials are not configured"]
            )
        credentials = base64.b64encode(
            f"{settings.censys_api_id}:{settings.censys_api_secret}".encode()
        ).decode()
        response = await self._get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers={"Authorization": f"Basic {credentials}"},
        )
        response.raise_for_status()
        result = response.json().get("result", {})
        services = result.get("services", [])
        return ConnectorResult(
            connector=self.name,
            evidence=[
                Evidence(
                    type="authorized_infrastructure",
                    value=ip,
                    source=self.name,
                    confidence=0.8,
                    reliability=SourceReliability.HIGH,
                    metadata={
                        "authorization_reference": self.authorization_reference,
                        "names": result.get("dns", {}).get("names", []),
                        "service_ports": sorted(
                            {
                                item.get("port")
                                for item in services
                                if item.get("port") is not None
                            }
                        ),
                        "last_updated_at": result.get("last_updated_at"),
                    },
                )
            ],
        )


async def run_connectors(
    connectors: list[BaseConnector], identifier: str
) -> list[ConnectorResult]:
    """Run independent sources concurrently within the configured resource limit."""
    semaphore = asyncio.Semaphore(settings.max_osint_concurrency)

    async def run(connector: BaseConnector) -> ConnectorResult:
        async with semaphore:
            try:
                return await connector.search(identifier)
            except Exception as exc:
                return ConnectorResult(
                    connector=connector.name,
                    errors=[f"{type(exc).__name__}: connector request failed"],
                )

    return await asyncio.gather(*(run(connector) for connector in connectors))
