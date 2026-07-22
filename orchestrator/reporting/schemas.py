"""Strict schemas for evidence-linked investigation reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    statement: str = Field(min_length=1, max_length=3000)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: RiskLevel = RiskLevel.LOW
    limitations: list[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    report_id: str = Field(
        default_factory=lambda: f"RPT-{uuid4().hex[:12].upper()}"
    )
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executive_summary: str = Field(min_length=1, max_length=5000)
    identity_confidence: str
    overall_risk: RiskLevel
    evidence_count: int = Field(ge=0)
    findings: list[Finding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    methodology: list[str] = Field(default_factory=list)
