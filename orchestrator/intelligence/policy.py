"""Authorization, minimization, and retention policy enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .models import InvestigationTarget


@dataclass(frozen=True)
class CollectionPolicy:
    authorization_reference: str
    purpose: str
    expires_at: datetime
    permitted_sources: frozenset[str]
    infrastructure_enrichment: bool = False

    def authorize(self, target: InvestigationTarget, source: str) -> None:
        if not target.authorization_confirmed:
            raise PermissionError("Written authorization is required")
        if not self.authorization_reference.strip():
            raise PermissionError("An authorization reference is required")
        if datetime.now(timezone.utc) >= self.expires_at:
            raise PermissionError("Authorization has expired")
        if source not in self.permitted_sources:
            raise PermissionError(f"Source is outside the approved scope: {source}")
        if source in {"shodan", "censys"} and not self.infrastructure_enrichment:
            raise PermissionError(
                "Infrastructure enrichment is outside the approved scope"
            )
