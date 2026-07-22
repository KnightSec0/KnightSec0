"""Connector interface shared by command-line and API data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

from intelligence.models import ConnectorResult


class BaseConnector(ABC):
    name: str
    identifier_type: str

    @abstractmethod
    async def search(self, identifier: str) -> ConnectorResult:
        """Search one authorized identifier and return normalized evidence."""
        raise NotImplementedError
