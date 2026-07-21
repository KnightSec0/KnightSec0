"""
Neo4j graph database client for DeepVault.
"""
import logging
from typing import Optional, Any
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession, Record
from ..config import settings

logger = logging.getLogger("deepvault.neo4j")


class Neo4jClient:
    """Async Neo4j client with connection pooling."""

    def __init__(self):
        self.driver: Optional[AsyncDriver] = None

    async def connect(self):
        if self.driver is None:
            self.driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                max_connection_lifetime=3600,
                connection_acquisition_timeout=30,
            )
            await self.driver.verify_connectivity()
            logger.info("Connected to Neo4j at %s", settings.neo4j_uri)

    async def close(self):
        if self.driver:
            await self.driver.close()
            self.driver = None

    async def session(self) -> AsyncSession:
        await self.connect()
        return self.driver.session()

    async def run_query(self, query: str, **params) -> list[Record]:
        async with await self.session() as session:
            result = await session.run(query, **params)
            return await result.data()

    async def create_constraints(self):
        """Create uniqueness constraints for deduplication."""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Person) REQUIRE p.investigation_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (e:EmailAddress) REQUIRE e.value IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:Username) REQUIRE u.value IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:PhoneNumber) REQUIRE p.value IS UNIQUE",
        ]
        async with await self.session() as session:
            for c in constraints:
                try:
                    await session.run(c)
                except Exception as e:
                    logger.warning("Constraint creation (non-critical): %s", e)
        logger.info("Neo4j constraints verified")
