"""Email service-footprint investigator using public registration signals."""

from __future__ import annotations

import asyncio
import logging

from config import settings
from connectors import HoleheConnector

logger = logging.getLogger("deepvault.investigators.email_footprint")


class EmailFootprintInvestigator:
    def __init__(self) -> None:
        self.connector = HoleheConnector()
        self._semaphore = asyncio.Semaphore(settings.max_osint_concurrency)

    async def _search(self, email: str):
        async with self._semaphore:
            return await self.connector.search(email)

    async def run(self, emails: list[str]) -> list[dict]:
        clean_emails = list(
            dict.fromkeys(email.strip().lower() for email in emails if email.strip())
        )
        results = await asyncio.gather(
            *(self._search(email) for email in clean_emails)
        ) if clean_emails else []

        output: list[dict] = []
        for result in results:
            for error in result.errors:
                if error:
                    logger.warning("%s: %s", result.connector, error)
            output.extend(item.safe_dump() for item in result.evidence)
        return output
