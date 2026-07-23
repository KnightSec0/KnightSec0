"""Strict schemas for evidence-linked investigation reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


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


class TimelineEvent(BaseModel):
    occurred_at: datetime
    description: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[str] = Field(min_length=1)


class Contradiction(BaseModel):
    description: str = Field(min_length=1, max_length=1500)
    evidence_ids: list[str] = Field(min_length=2)
    recommendation: str = Field(min_length=1, max_length=1000)


class SourceCoverage(BaseModel):
    source: str
    evidence_count: int = Field(ge=0)
    status: str
    evidence_ids: list[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    report_id: str = Field(default_factory=lambda: f"RPT-{uuid4().hex[:12].upper()}")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executive_summary: str = Field(min_length=1, max_length=5000)
    executive_summary_evidence_ids: list[str] = Field(default_factory=list)
    identity_confidence: str
    overall_risk: RiskLevel
    evidence_count: int = Field(ge=0)
    findings: list[Finding] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    source_coverage: list[SourceCoverage] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    methodology: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_summary_citations(self) -> "InvestigationReport":
        if self.evidence_count and not self.executive_summary_evidence_ids:
            raise ValueError("Evidence-backed executive summaries require evidence IDs")
        return self
