"""Normalized evidence models used by every DeepVault connector."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class IdentityStatus(str, Enum):
    CONFIRMED = "confirmed"
    HIGHLY_PROBABLE = "highly_probable"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNRELATED = "unrelated"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class SourceReliability(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class InvestigationTarget(BaseModel):
    """Identifiers supplied for an authorized person-focused investigation."""

    name: str = Field(min_length=1, max_length=255)
    aliases: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    employer: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    lawful_purpose: str = Field(min_length=8, max_length=500)
    authorization_confirmed: bool = False

    @field_validator("emails")
    @classmethod
    def validate_emails(cls, values: list[str]) -> list[str]:
        pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
        invalid = [value for value in values if not pattern.match(value)]
        if invalid:
            raise ValueError(f"Invalid email address(es): {invalid}")
        return list(dict.fromkeys(value.strip().lower() for value in values))

    @model_validator(mode="after")
    def require_authorization(self) -> "InvestigationTarget":
        if not self.authorization_confirmed:
            raise ValueError("Written authorization must be confirmed before collection starts")
        return self


class Evidence(BaseModel):
    """One source-backed observation. It is not automatically an identity claim."""

    id: str = Field(default_factory=lambda: f"EVID-{uuid4().hex[:12].upper()}")
    type: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=2000)
    source: str = Field(min_length=1, max_length=100)
    source_url: str | None = Field(default=None, max_length=2000)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reliability: SourceReliability = SourceReliability.UNKNOWN
    identity_status: IdentityStatus = IdentityStatus.INSUFFICIENT_EVIDENCE
    authorization_reference: str | None = Field(default=None, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list)
    independence_group: str | None = Field(default=None, max_length=100)
    tool_version: str | None = Field(default=None, max_length=100)
    corroborated_by: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("type", "value", "source")
    @classmethod
    def strip_required_strings(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Evidence strings cannot be blank")
        return cleaned

    @field_validator("evidence_ids", "corroborated_by")
    @classmethod
    def unique_string_lists(cls, values: list[str]) -> list[str]:
        return list(
            dict.fromkeys(
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            )
        )

    def safe_dump(self) -> dict[str, Any]:
        """Return an LLM-safe representation with credential-like fields removed."""
        from .redaction import redact_sensitive

        return redact_sensitive(self.model_dump(mode="json"))


class ConnectorResult(BaseModel):
    connector: str
    evidence: list[Evidence] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_ms: int = Field(default=0, ge=0)
