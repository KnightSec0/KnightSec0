"""Person-focused social profile discovery with independent corroboration."""

from __future__ import annotations

import asyncio
import logging

from config import settings
from connectors import MaigretConnector, SherlockConnector
from intelligence.correlation import correlate_evidence
from intelligence.models import ConnectorResult, Evidence

logger = logging.getLogger("deepvault.investigators.social")


def _confidence_label(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


class SocialMediaInvestigator:
    """Run username connectors in parallel and preserve source provenance."""

    def __init__(self) -> None:
        self.connectors = [SherlockConnector(), MaigretConnector()]
        self._semaphore = asyncio.Semaphore(settings.max_osint_concurrency)

    async def _search(
        self, connector: SherlockConnector | MaigretConnector, username: str
    ) -> ConnectorResult:
        async with self._semaphore:
            return await connector.search(username)

    async def run(self, usernames: list[str]) -> list[dict]:
        clean_usernames = list(
            dict.fromkeys(username.strip() for username in usernames if username.strip())
        )
        logger.info("Social profile search for %s username(s)", len(clean_usernames))

        tasks = [
            self._search(connector, username)
            for username in clean_usernames
            for connector in self.connectors
        ]
        connector_results = await asyncio.gather(*tasks) if tasks else []

        raw_evidence: list[Evidence] = []
        for result in connector_results:
            raw_evidence.extend(result.evidence)
            for error in result.errors:
                if error:
                    logger.warning("%s: %s", result.connector, error)

        correlated = correlate_evidence(raw_evidence)
        results: list[dict] = []
        for item in correlated:
            username = ""
            observations = item.metadata.get("observations", [])
            if observations:
                username = (
                    observations[0].get("metadata", {}).get("username", "")
                )
            results.append(
                {
                    "username": username,
                    "source": item.source,
                    "url": item.value,
                    "confidence": _confidence_label(item.confidence),
                    "confidence_score": item.confidence,
                    "identity_status": item.identity_status.value,
                    "corroborated_by": item.corroborated_by,
                    "evidence": item.safe_dump(),
                }
            )
        return results
