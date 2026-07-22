"""
SQLAlchemy models for DeepVault.
"""
import uuid
import enum
import datetime
from typing import Optional

from sqlalchemy import (
    Column, String, JSON, DateTime, ForeignKey, Enum as SAEnum, Text, Integer,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class InvestigationStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_aliases: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    target_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    target_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    target_phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        SAEnum(InvestigationStatus), default=InvestigationStatus.PENDING, index=True
    )
    depth: Mapped[str] = mapped_column(String(10), default="full")
    risk_score: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    updated_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime, onupdate=datetime.datetime.utcnow, nullable=True
    )
    completed_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime, nullable=True)
    case_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON, default=dict)

    artifacts = relationship("Artifact", back_populates="investigation",
                              cascade="all, delete-orphan",
                              lazy="selectin")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"),
        index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    identifier_type: Mapped[str] = mapped_column(String(50), nullable=False)
    identifier_value: Mapped[str] = mapped_column(String(500), nullable=False)
    context: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    first_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    screenshot_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    investigation = relationship("Investigation", back_populates="artifacts")
