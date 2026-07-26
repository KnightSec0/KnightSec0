"""Produce reviewable transform choices; never execute pivots automatically."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .base import TransformEntity
from .registry import TransformRegistry


class PlannedTransform(BaseModel):
    transform: str
    entity_type: str
    value: str
    evidence_ids: list[str] = Field(default_factory=list)
    pivot_depth: int = Field(ge=0)
    execution_mode: str = "analyst_confirmation_required"


class TransformPlanner:
    def __init__(self, registry: TransformRegistry) -> None:
        self.registry = registry

    def choices(
        self,
        entity: TransformEntity,
        *,
        permitted_transforms: set[str],
        pivot_depth: int,
    ) -> list[PlannedTransform]:
        return [
            PlannedTransform(
                transform=spec.name,
                entity_type=entity.type,
                value=entity.value,
                evidence_ids=entity.evidence_ids,
                pivot_depth=pivot_depth,
            )
            for spec in self.registry.applicable(entity.type)
            if spec.name in permitted_transforms
        ]
