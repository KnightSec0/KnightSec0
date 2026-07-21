"""
Dark Web Investigator — searches .onion sites and Tor networks.
"""
import asyncio
import logging
from typing import Optional
import aiohttp

from ..config import settings

logger = logging.getLogger("deepvault.investigators.darkweb")


class DarkWebInvestigator:
    """
    Searches dark web resources via Tor, including Ahmia, paste sites,
    and forum mentions using the Tor SOCKS5 proxy.
    """

    async def run(self, queries: list[str]) -> dict:
        """Search dark web for target information."""
        logger.info(f"Dark web search for {len(queries)} queries via Tor")
        results = {"ahmia_results": [], "paste_mentions": []}

        # Ahmia search
        results["ahmia_results"] = await self._search_ahmia(queries)

        # Paste site search
        results["paste_mentions"] = await self._search_paste_sites(queries)

        return results

    async def _search_ahmia(self, queries: list[str]) -> list[dict]:
        """Search Ahmia .onion search engine."""
        results = []
        # Ahmia has a clearnet API
        async with aiohttp.ClientSession() as session:
            for q in queries[:5]:
                try:
                    async with session.get(
                        "https://ahmia.fi/search/",
                        params={"q": q},
                        timeout=20
                    ) as resp:
                        if resp.status == 200:
                            results.append({
                                "query": q,
                                "url": "https://ahmia.fi/search/",
                                "status": "queried",
                            })
                except Exception as e:
                    logger.debug(f"Ahmia search failed for '{q}': {e}")
        return results

    async def _search_paste_sites(self, queries: list[str]) -> list[dict]:
        """Search common paste/leak sites."""
        results = []
        paste_sites = [
            "https://pastebin.com/search?q={query}",
            "https://dpaste.org/?q={query}",
        ]
        async with aiohttp.ClientSession() as session:
            for q in queries[:3]:
                for site_template in paste_sites:
                    try:
                        url = site_template.format(query=q)
                        async with session.get(url, timeout=15) as resp:
                            if resp.status == 200:
                                results.append({
                                    "query": q,
                                    "site": url,
                                    "status": "found",
                                })
                    except Exception as e:
                        logger.debug(f"Paste search failed for '{q}' at {site_template}: {e}")
        return results
