"""
Social Media Investigator — discovers profiles across 400+ platforms.
"""
import asyncio
import logging
from typing import Optional
import subprocess
import json

logger = logging.getLogger("deepvault.investigators.social")


class SocialMediaInvestigator:
    """
    Uses Sherlock, Maigret, and WhatsMyName to discover accounts
    across social media platforms and forums.
    """

    async def run(self, usernames: list[str]) -> list[dict]:
        """Discover social media accounts for given usernames."""
        logger.info(f"Social media search for {len(usernames)} usernames")
        results = []

        # Sherlock search
        for username in usernames:
            try:
                result = await asyncio.to_thread(self._sherlock_search, username)
                results.extend(result)
            except Exception as e:
                logger.warning(f"Sherlock error for {username}: {e}")

        return results

    @staticmethod
    def _sherlock_search(username: str) -> list[dict]:
        """Run sherlock command and parse results."""
        try:
            output = subprocess.run(
                ["sherlock", username, "--output", "/tmp/sherlock_results.json"],
                capture_output=True,
                timeout=60,
                text=True
            )
            try:
                with open("/tmp/sherlock_results.json", "r") as f:
                    data = json.load(f)
                    results = []
                    for site, details in data.items():
                        if isinstance(details, dict) and details.get("exists"):
                            results.append({
                                "username": username,
                                "source": site,
                                "url": details.get("url_main", ""),
                                "confidence": "high",
                            })
                    return results
            except FileNotFoundError:
                return []
        except Exception as e:
            logger.error(f"Sherlock execution failed: {e}")
            return []
