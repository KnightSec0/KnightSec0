"""
Identity Investigator — expands a name into emails, phones, usernames, addresses.
"""
import asyncio
import logging
import re
from typing import Optional

import aiohttp
from bs4 import BeautifulSoup

from config import settings

logger = logging.getLogger("deepvault.investigators.identity")


class IdentityInvestigator:
    """
    Takes a person's name and generates permutations, then searches
    public sources for associated identifiers (emails, phones, addresses).
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

    # ------------------------------------------------------------------
    # Name permutations
    # ------------------------------------------------------------------
    @staticmethod
    def generate_email_permutations(first: str, last: str) -> list[str]:
        """Generate common email local-part patterns from a name."""
        f = first.lower().strip()
        l = last.lower().strip()
        fi = f[0] if f else ""
        li = l[0] if l else ""

        patterns = [
            f, l,
            f"{f}.{l}", f"{f}{l}", f"{f}_{l}",
            f"{fi}{l}", f"{f}.{li}", f"{fi}.{l}",
            f"{l}.{f}", f"{l}{f}", f"{l}_{f}",
            f"{f}-{l}", f"{fi}{li}",
            f"{f}{li}", f"{fi}{l}123",
            f"{f}.{l}1", f"{f}1",
        ]
        return list(set(patterns))

    @staticmethod
    def generate_username_permutations(first: str, last: str) -> list[str]:
        """Generate likely usernames from a name."""
        f = first.lower().strip()
        l = last.lower().strip()
        fi = f[0] if f else ""
        li = l[0] if l else ""
        patterns = [
            f, l,
            f"{f}{l}", f"{f}.{l}", f"{f}_{l}",
            f"{fi}{l}", f"{l}{fi}", f"{l}{f}",
            f"{f}{li}", f"{fi}{li}",
            f"{f}.{li}", f"{fi}.{l}",
            f"{l}.{fi}", f"{fi}{l}123",
        ]
        return list(set(patterns))

    # ------------------------------------------------------------------
    # Hunter.io email finder
    # ------------------------------------------------------------------
    async def search_hunter_io(self, first: str, last: str, domain: str = "gmail.com") -> list[dict]:
        if not settings.hunter_api_key:
            logger.debug("No Hunter API key configured, skipping Hunter.io lookup")
            return []

        url = "https://api.hunter.io/v2/email-finder"
        params = {
            "api_key": settings.hunter_api_key,
            "first_name": first,
            "last_name": last,
            "domain": domain,
        }
        try:
            async with self.session.get(url, params=params, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    record = data.get("data", {})
                    emails = record.get("emails") or []
                    if record.get("email"):
                        emails = [{
                            "value": record.get("email"),
                            "type": record.get("type", "unknown"),
                            "confidence": record.get("score", record.get("confidence", 0)),
                        }]
                    return [
                        {
                            "email": e.get("value"),
                            "type": e.get("type", "unknown"),
                            "confidence": e.get("confidence", 0),
                        }
                        for e in emails
                        if e.get("value")
                    ]
                elif resp.status == 404:
                    return []
                else:
                    logger.warning("Hunter.io returned %s: %s", resp.status, await resp.text())
                    return []
        except asyncio.TimeoutError:
            logger.warning("Hunter.io request timed out")
            return []
        except Exception as e:
            logger.error("Hunter.io error: %s", e)
            return []

    # ------------------------------------------------------------------
    # Google dorking for personal info
    # ------------------------------------------------------------------
    async def google_dork_person(self, name: str) -> list[dict]:
        """Use Google Custom Search API to find profile pages."""
        if not settings.brave_api_key:
            return []

        url = "https://api.search.brave.com/res/v1/web/search"
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": settings.brave_api_key,
        }

        queries = [
            f'"{name}" site:linkedin.com/in/',
            f'"{name}" site:github.com',
            f'"{name}" "resume" OR "CV" filetype:pdf',
            f'"{name}" "security" OR "cybersecurity" OR "engineer"',
        ]

        results = []
        for q in queries:
            try:
                params = {"q": q, "count": 10}
                async with self.session.get(url, headers=headers, params=params, timeout=20) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("web", {}).get("results", []):
                            results.append({
                                "url": item.get("url"),
                                "title": item.get("title"),
                                "description": item.get("description"),
                                "search_query": q,
                                "source": "brave_search",
                            })
                    await asyncio.sleep(0.5)  # rate limit
            except Exception as e:
                logger.debug("Search query failed '%s': %s", q, e)

        return results

    # ------------------------------------------------------------------
    # Extract emails from text
    # ------------------------------------------------------------------
    @staticmethod
    def extract_emails(text: str) -> list[str]:
        return list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))

    @staticmethod
    def extract_phones(text: str) -> list[str]:
        patterns = [
            r"\+?1?\d{10,15}",
            r"\(\d{3}\)\s?\d{3}-?\d{4}",
            r"\d{3}-\d{3}-\d{4}",
        ]
        phones = []
        for p in patterns:
            phones.extend(re.findall(p, text))
        return list(set(phones))

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------
    async def run(self, first_name: str, last_name: str, domains: Optional[list[str]] = None) -> dict:
        """Full identity expansion pipeline."""
        logger.info("Identity investigation for %s %s", first_name, last_name)

        self.session = aiohttp.ClientSession(
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/125.0.0.0 Safari/537.36"}
        )

        try:
            email_perms = self.generate_email_permutations(first_name, last_name)
            username_perms = self.generate_username_permutations(first_name, last_name)

            # Hunter is meaningful for known organizational domains only.
            # Do not enumerate consumer-mail domains from a person's name.
            hunter_results = []
            for domain in domains or []:
                h = await self.search_hunter_io(first_name, last_name, domain)
                hunter_results.extend(h)

            # Brave/Google search
            name_full = f"{first_name} {last_name}"
            search_results = await self.google_dork_person(name_full)

            # Extract identifiers from search results
            all_text = " ".join(
                [r.get("title", "") + " " + r.get("description", "") for r in search_results]
            )
            found_emails = self.extract_emails(all_text)
            # Add hunter results
            found_emails.extend([h["email"] for h in hunter_results if h.get("email")])
            found_emails = list(set(found_emails))

            found_phones = []  # Disabled by default: avoid aggregating personal phone data.

            # Common usernames from social URLs
            found_usernames = []
            for r in search_results:
                url = r.get("url", "")
                for match in re.finditer(r"(?:linkedin\.com/in/|github\.com/|twitter\.com/|facebook\.com/)([^/?#]+)", url):
                    found_usernames.append(match.group(1))
            found_usernames = list(set(found_usernames))

            return {
                "permutations": email_perms,
                "username_permutations": username_perms,
                "emails_found": found_emails,
                "phones_found": found_phones,
                "usernames_found": found_usernames,
                "profiles_found": search_results,
                "hunter_results": hunter_results,
            }

        finally:
            await self.session.close()
