"""
Breach Investigator — checks data breach databases (HIBP, DeHashed, IntelX).
"""

import asyncio
import logging
import aiohttp

from config import settings
from intelligence.redaction import redact_sensitive

logger = logging.getLogger("deepvault.investigators.breach")


class BreachInvestigator:
    """
    Queries Have I Been Pwned, DeHashed, and Intelligence X
    to find exposed credentials and data breaches.
    """

    async def run(
        self,
        emails: list[str],
        usernames: list[str],
        *,
        excluded_sources: set[str] | None = None,
    ) -> dict:
        """Check for email/username in breach databases."""
        logger.info(
            f"Breach search for {len(emails)} emails, {len(usernames)} usernames"
        )
        results = {}

        excluded = excluded_sources or set()

        # HIBP
        if settings.hibp_api_key and "hibp" not in excluded:
            results["hibp"] = await self._check_hibp(emails)

        # DeHashed
        if settings.dehashed_api_key and "dehashed" not in excluded:
            results["dehashed"] = await self._check_dehashed(emails)

        # IntelX
        if settings.intelx_api_key and "intelx" not in excluded:
            results["intelx"] = await self._check_intelx(emails + usernames)

        return results

    async def _check_hibp(self, emails: list[str]) -> list[dict]:
        """Check Have I Been Pwned API."""
        headers = {
            "User-Agent": "SIGMA-WorldAtlas/1.0",
            "hibp-api-key": settings.hibp_api_key,
        }
        results = []
        async with aiohttp.ClientSession(headers=headers) as session:
            for email in emails:
                try:
                    async with session.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                        timeout=15,
                    ) as resp:
                        if resp.status == 200:
                            breaches = await resp.json()
                            for breach in breaches:
                                results.append(
                                    {
                                        "email": email,
                                        "breach_name": breach.get("Name"),
                                        "breach_date": breach.get("BreachDate"),
                                        "compromised_data": breach.get(
                                            "DataClasses", []
                                        ),
                                        "source": "hibp",
                                    }
                                )
                        await asyncio.sleep(1.5)  # HIBP rate limit
                except Exception as e:
                    logger.debug(f"HIBP check failed for {email}: {e}")
        return results

    async def _check_dehashed(self, emails: list[str]) -> list[dict]:
        """Check DeHashed API."""
        if not settings.dehashed_api_login:
            return []
        results = []
        async with aiohttp.ClientSession() as session:
            for email in emails:
                try:
                    async with session.get(
                        f"https://api.dehashed.com/search?query={email}&size=100",
                        auth=aiohttp.BasicAuth(
                            settings.dehashed_api_login, settings.dehashed_api_key
                        ),
                        timeout=15,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for entry in data.get("entries", []):
                                results.append(
                                    {
                                        "email": email,
                                        "username": entry.get("username"),
                                        "credential_data_present": bool(
                                            entry.get("password")
                                            or entry.get("hashed_password")
                                            or entry.get("hash")
                                        ),
                                        "database": entry.get("database_name"),
                                        "leaked_date": entry.get("leak_date"),
                                        "source": "dehashed",
                                    }
                                )
                except Exception as e:
                    logger.debug(f"DeHashed check failed for {email}: {e}")
        return results

    async def _check_intelx(self, queries: list[str]) -> list[dict]:
        """Check Intelligence X API."""
        if not settings.intelx_api_key:
            return []
        results = []
        async with aiohttp.ClientSession() as session:
            for query in queries[:10]:  # Limit to 10 queries
                try:
                    async with session.post(
                        "https://2.intelx.io/phonebook/search",
                        json={
                            "term": query,
                            "buckets": [],
                            "lookuplevel": 0,
                            "maxresults": 50,
                            "timeout": 10,
                        },
                        headers={"x-key": settings.intelx_api_key},
                        timeout=20,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for entry in data.get("records", []):
                                results.append(
                                    {
                                        "query": query,
                                        "record": redact_sensitive(entry),
                                        "source": "intelx",
                                    }
                                )
                except Exception as e:
                    logger.debug(f"IntelX check failed for {query}: {e}")
        return results
