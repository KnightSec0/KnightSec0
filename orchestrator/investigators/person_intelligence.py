"""Policy-gated orchestration for normalized person intelligence sources."""

from __future__ import annotations

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
                ShodanConnector(),
                CensysConnector(),
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
