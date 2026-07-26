"""Contracts shared by API-backed, CLI-backed, and offline transforms."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from intelligence.models import ConnectorResult


class TransformEntity(BaseModel):
    """One explicit transform input selected by an analyst."""

    type: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("type", "value")
    @classmethod
    def strip_strings(cls, value: str) -> str:
        return value.strip()

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class TransformContext(BaseModel):
    """Authorization and execution context which must accompany every transform."""

    case_id: str = Field(min_length=1, max_length=100)
    authorization_reference: str = Field(min_length=1, max_length=200)
    lawful_purpose: str = Field(min_length=8, max_length=500)
    authorization_expires_at: datetime
    permitted_transforms: set[str] = Field(default_factory=set)
    authorized_domains: set[str] = Field(default_factory=set)
    authorized_ips: set[str] = Field(default_factory=set)
    pivot_depth: int = Field(default=0, ge=0)
    allow_infrastructure_enrichment: bool = False
    allow_authenticated_transforms: bool = False
    allow_sensitive_pivots: bool = False

    @model_validator(mode="after")
    def require_current_authorization(self) -> "TransformContext":
        expiry = self.authorization_expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
            self.authorization_expires_at = expiry
        if expiry <= datetime.now(timezone.utc):
            raise ValueError("Transform authorization has expired")
        return self


class TransformSpec(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    title: str = Field(min_length=1, max_length=100)
    accepted_entity_types: set[str] = Field(min_length=1)
    produced_entity_types: set[str] = Field(default_factory=set)
    passive: bool = True
    manual_only: bool = False
    authenticated: bool = False
    priority: Literal["p0", "p1", "p2"] = "p2"
    independence_group: str | None = Field(default=None, max_length=100)
    description: str = Field(default="", max_length=500)


class TransformAdapter(ABC):
    """Execute one bounded transform and return normalized evidence only."""

    spec: TransformSpec

    @abstractmethod
    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        raise NotImplementedError
