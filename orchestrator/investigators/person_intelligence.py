"""Policy-gated orchestration for normalized person intelligence sources."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from connectors import (
    BravePersonSearchConnector,
    CensysConnector,
    GitHubProfileConnector,
    HIBPConnector,
    HunterConnector,
    HoleheConnector,
    MaigretConnector,
    SherlockConnector,
    ShodanConnector,
    SpiderFootConnector,
)
from intelligence.models import ConnectorResult, InvestigationTarget
from intelligence.policy import CollectionPolicy


@dataclass(frozen=True)
class CollectionRequest:
    source: str
    identifier: str
    identifier_type: str


class PersonIntelligenceInvestigator:
    """Dispatch only explicitly scoped identifiers to explicitly approved sources."""

    def __init__(self, policy: CollectionPolicy) -> None:
        self.policy = policy
        self.connectors = {
            item.name: item
            for item in (
                GitHubProfileConnector(),
                HIBPConnector(),
                HunterConnector(),
                BravePersonSearchConnector(),
                SpiderFootConnector(),
                ShodanConnector(
                    authorization_reference=policy.authorization_reference,
                    infrastructure_enrichment=policy.infrastructure_enrichment,
                ),
                CensysConnector(
                    authorization_reference=policy.authorization_reference,
                    infrastructure_enrichment=policy.infrastructure_enrichment,
                ),
                SherlockConnector(),
                MaigretConnector(),
                HoleheConnector(),
            )
        }

    async def collect(
        self,
        *,
        target: InvestigationTarget,
        source: str,
        identifier: str,
    ) -> ConnectorResult:
        self.policy.authorize(target, source)
        connector = self.connectors.get(source)
        if connector is None:
            raise ValueError(f"Unknown connector: {source}")
        return await connector.search(identifier)

    def build_plan(
        self,
        *,
        target: InvestigationTarget,
        authorized_ips: list[str] | None = None,
    ) -> list[CollectionRequest]:
        """Build a deduplicated, source-appropriate collection plan."""
        requests: list[CollectionRequest] = []
        usernames = list(dict.fromkeys(target.usernames))
        emails = list(dict.fromkeys(target.emails))
        domains = list(dict.fromkeys(target.domains))

        for username in usernames:
            for source in ("github", "sherlock", "maigret"):
                requests.append(CollectionRequest(source, username, "username"))
        for email in emails:
            for source in ("hibp", "hunter", "holehe"):
                requests.append(CollectionRequest(source, email, "email"))

        person_query = " ".join(
            part for part in (target.name, target.employer, target.location) if part
        )
        requests.append(CollectionRequest("brave", person_query, "person_query"))

        for value in [*domains, *usernames]:
            requests.append(CollectionRequest("spiderfoot", value, "passive_target"))
        for ip in authorized_ips or []:
            requests.append(CollectionRequest("shodan", ip, "authorized_ip"))
            requests.append(CollectionRequest("censys", ip, "authorized_ip"))

        permitted = self.policy.permitted_sources
        unique: dict[tuple[str, str], CollectionRequest] = {}
        for request in requests:
            if request.source in permitted and request.identifier.strip():
                unique[(request.source, request.identifier)] = request
        return list(unique.values())

    async def collect_plan(
        self,
        *,
        target: InvestigationTarget,
        authorized_ips: list[str] | None = None,
        concurrency: int = 4,
    ) -> list[tuple[CollectionRequest, ConnectorResult]]:
        """Execute a plan without allowing one source failure to abort the case."""
        semaphore = asyncio.Semaphore(max(1, concurrency))

        async def run(
            request: CollectionRequest,
        ) -> tuple[CollectionRequest, ConnectorResult]:
            async with semaphore:
                try:
                    result = await self.collect(
                        target=target,
                        source=request.source,
                        identifier=request.identifier,
                    )
                except PermissionError as exc:
                    result = ConnectorResult(
                        connector=request.source,
                        errors=[str(exc)[:500]],
                    )
                except Exception as exc:
                    result = ConnectorResult(
                        connector=request.source,
                        errors=[f"{type(exc).__name__}: connector request failed"],
                    )
                return request, result

        return await asyncio.gather(
            *(
                run(request)
                for request in self.build_plan(
                    target=target, authorized_ips=authorized_ips
                )
            )
        )
