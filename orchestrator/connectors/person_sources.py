"""API-backed person intelligence connectors with normalized provenance."""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import ipaddress
import json
import time
from typing import Any
from urllib.parse import quote
from urllib.parse import urlsplit

import httpx

from config import settings
from intelligence.models import (
    ConnectorResult,
    Evidence,
    IdentityStatus,
    SourceReliability,
)
from intelligence.redaction import redact_sensitive

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


_SPIDERFOOT_BLOCKED_EVENT_PARTS = {
    "PASSWORD",
    "CREDIT_CARD",
    "IBAN",
    "COOKIE",
    "HASH",
    "PRIVATE_KEY",
    "RAW_DATA",
    "RAW_RIR",
    "DARKNET",
    "ONION",
}
_SPIDERFOOT_EVENT_TYPES = {
    "EMAILADDR": "email_observation",
    "EMAILADDR_GENERIC": "email_observation",
    "USERNAME": "username_observation",
    "SOCIAL_MEDIA": "social_profile",
    "SOCIAL_MEDIA_OWNED": "social_profile",
    "INTERNET_NAME": "domain_observation",
    "DOMAIN_NAME": "domain_observation",
    "PARENT_DOMAIN": "domain_observation",
    "IP_ADDRESS": "infrastructure_observation",
    "IPV6_ADDRESS": "infrastructure_observation",
    "PHONE_NUMBER": "phone_observation",
    "HUMAN_NAME": "person_name_observation",
    "COMPANY_NAME": "organization_observation",
    "LINKED_URL_INTERNAL": "web_observation",
    "LINKED_URL_EXTERNAL": "web_observation",
    "URL_FORM": "web_observation",
    "WEB_ANALYTICS_ID": "web_observation",
    "PROVIDER_DNS": "service",
    "PROVIDER_EMAIL": "service",
    "ACCOUNT_EXTERNAL_OWNED": "service",
}


def _spiderfoot_start_id(payload: Any) -> str | None:
    if (
        isinstance(payload, list)
        and len(payload) >= 2
        and str(payload[0]).upper() == "SUCCESS"
    ):
        value = str(payload[1]).strip()
        return value[:200] if value else None
    if isinstance(payload, str):
        value = payload.strip().strip('"')
        return value[:200] if value else None
    return None


def _spiderfoot_status(payload: Any) -> str | None:
    if isinstance(payload, list) and len(payload) >= 6:
        return str(payload[5]).strip().upper()
    if isinstance(payload, dict):
        value = payload.get("status")
        return str(value).strip().upper() if value else None
    return None


def _spiderfoot_source_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    return None


def _spiderfoot_evidence(
    payload: Any,
    *,
    scan_id: str,
    target: str,
) -> list[Evidence]:
    """Normalize a bounded SpiderFoot JSON export without sensitive payloads."""
    if not isinstance(payload, list):
        return []
    evidence: list[Evidence] = []
    seen: set[tuple[str, str, str]] = set()
    for item in payload[: settings.max_results_per_transform * 4]:
        if not isinstance(item, dict):
            continue
        event_type = str(item.get("event_type") or "").strip().upper()
        if not event_type or any(
            part in event_type for part in _SPIDERFOOT_BLOCKED_EVENT_PARTS
        ):
            continue
        false_positive = item.get("false_positive")
        if false_positive in {True, 1, "1", "true", "True", "yes"}:
            continue
        normalized_type = _SPIDERFOOT_EVENT_TYPES.get(event_type)
        if normalized_type is None:
            continue
        value = str(item.get("data") or "").strip()
        if not value or len(value) > 2000 or "<redacted" in value.casefold():
            continue
        module = str(item.get("module") or "unknown").strip()[:120]
        key = (normalized_type, value.casefold(), module.casefold())
        if key in seen:
            continue
        seen.add(key)
        metadata = redact_sensitive(
            {
                "spiderfoot_scan_id": scan_id,
                "spiderfoot_event_type": event_type,
                "module": module,
                "scan_target": target,
                "last_seen": str(item.get("last_seen") or "")[:50] or None,
                "collection_mode": "passive",
            }
        )
        evidence.append(
            Evidence(
                type=normalized_type,
                value=value,
                source="spiderfoot",
                source_url=_spiderfoot_source_url(value),
                confidence=0.48,
                reliability=SourceReliability.MEDIUM,
                identity_status=IdentityStatus.POSSIBLE
                if normalized_type in {"social_profile", "username_observation"}
                else IdentityStatus.INSUFFICIENT_EVIDENCE,
                independence_group=f"spiderfoot:{module.casefold()}",
                notes=[
                    "SpiderFoot returned a passive source observation.",
                    "The observation requires source-level validation before attribution.",
                ],
                metadata=metadata,
            )
        )
        if len(evidence) >= settings.max_results_per_transform:
            break
    return evidence


class SpiderFootConnector(HTTPConnector):
    """Run and import an explicitly configured passive SpiderFoot scan."""

    name = "spiderfoot"
    identifier_type = "target"

    async def search(self, identifier: str) -> ConnectorResult:
        started = time.monotonic()
        if not settings.spiderfoot_url:
            return ConnectorResult(
                connector=self.name, errors=["SPIDERFOOT_URL is not configured"]
            )
        async with httpx.AsyncClient(timeout=settings.connector_timeout) as client:
            response = await client.post(
                f"{settings.spiderfoot_url.rstrip('/')}/startscan",
                headers={"Accept": "application/json"},
                data={
                    "scanname": f"DeepVault passive {datetime.now(timezone.utc).isoformat()}",
                    "scantarget": identifier,
                    "modulelist": "",
                    "typelist": "",
                    "usecase": "passive",
                },
            )
            response.raise_for_status()
            try:
                start_payload = response.json()
            except (json.JSONDecodeError, ValueError):
                start_payload = response.text
            scan_id = _spiderfoot_start_id(start_payload)
            if not scan_id:
                return ConnectorResult(
                    connector=self.name,
                    errors=["SpiderFoot rejected the passive scan request"],
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

            deadline = time.monotonic() + max(1, settings.spiderfoot_max_wait)
            terminal_status = None
            while time.monotonic() < deadline:
                status_response = await client.get(
                    f"{settings.spiderfoot_url.rstrip('/')}/scanstatus",
                    params={"id": scan_id},
                )
                status_response.raise_for_status()
                terminal_status = _spiderfoot_status(status_response.json())
                if terminal_status == "FINISHED":
                    break
                if terminal_status in {
                    "ABORTED",
                    "ERROR-FAILED",
                    "FAILED",
                    "ERROR",
                }:
                    return ConnectorResult(
                        connector=self.name,
                        errors=[f"SpiderFoot scan ended in state {terminal_status}"],
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                await asyncio.sleep(max(0.2, settings.spiderfoot_poll_interval))

            if terminal_status != "FINISHED":
                return ConnectorResult(
                    connector=self.name,
                    errors=["SpiderFoot scan timed out before result export"],
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

            export_response = await client.post(
                f"{settings.spiderfoot_url.rstrip('/')}/scanexportjsonmulti",
                data={"ids": scan_id},
            )
            export_response.raise_for_status()
            if len(export_response.content) > settings.max_transform_output_bytes:
                return ConnectorResult(
                    connector=self.name,
                    errors=["SpiderFoot result export exceeded the configured limit"],
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            try:
                export_payload = export_response.json()
            except (json.JSONDecodeError, ValueError):
                return ConnectorResult(
                    connector=self.name,
                    errors=["SpiderFoot returned an invalid result export"],
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
        evidence = _spiderfoot_evidence(
            export_payload,
            scan_id=scan_id,
            target=identifier,
        )
        return ConnectorResult(
            connector=self.name,
            evidence=evidence,
            errors=[] if evidence else ["SpiderFoot scan completed with no safe results"],
            duration_ms=int((time.monotonic() - started) * 1000),
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
