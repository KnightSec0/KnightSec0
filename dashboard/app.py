"""Local FastAPI dashboard for authorized DeepVault investigations."""

from __future__ import annotations

import asyncio
import csv
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from html import escape
import ipaddress
import io
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote_plus, urlsplit
from uuid import UUID, uuid4
from xml.etree import ElementTree as ET

from celery import Celery
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import DateTime, ForeignKey, JSON, String, func, select
from sqlalchemy.dialects.postgresql import ENUM as PGEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    target_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_aliases: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    target_username: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    target_email: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    target_phone: Mapped[str | None] = mapped_column(
        String(50), nullable=True, index=True
    )
    status: Mapped[InvestigationStatus] = mapped_column(
        PGEnum(
            InvestigationStatus,
            name="investigationstatus",
        ),
        default=InvestigationStatus.PENDING,
        index=True,
    )
    depth: Mapped[str] = mapped_column(String(10), default="surface")
    risk_score: Mapped[str | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    case_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSON, default=dict
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    investigation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    identifier_type: Mapped[str] = mapped_column(String(50), nullable=False)
    identifier_value: Mapped[str] = mapped_column(String(500), nullable=False)
    context: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=dict)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    screenshot_url: Mapped[str | None] = mapped_column(String(500), nullable=True)


_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_BEARER = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}")
_BASIC_AUTH = re.compile(r"(?i)basic\s+[a-z0-9+/=]{8,}")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:api[_-]?key|access[_-]?token|key|password|secret|token)=)[^&\s]+"
)
_LONG_SECRET = re.compile(r"\b[a-zA-Z0-9_-]{40,}\b")
_SENSITIVE_KEY_PARTS = {
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "hash",
    "message_body",
    "password",
    "private_communication",
    "private_key",
    "private_message",
    "raw_leak",
    "raw_record",
    "secret",
    "session",
    "token",
}
_ALLOWED_SOURCES = {
    "github",
    "gravatar",
    "sherlock",
    "maigret",
    "holehe",
    "hibp",
    "hunter",
    "brave",
    "spiderfoot",
    "shodan",
    "censys",
    "blackbird",
    "theharvester",
    "subfinder",
    "httpx",
    "ghunt",
    "exiftool",
    "tesseract",
    "poppler",
}
_RESERVED_OSINT_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "localhost",
}
_RESERVED_OSINT_SUFFIXES = (".example", ".invalid", ".local", ".localhost", ".test")
_TRANSFORM_CATALOG = {
    "spiderfoot": {
        "title": "SpiderFoot passive scan",
        "accepted_entity_types": ["username", "email", "domain", "hostname", "ip"],
        "passive": True,
        "authenticated": False,
        "priority": "p0",
    },
    "sherlock": {
        "title": "Sherlock username discovery",
        "accepted_entity_types": ["username"],
        "passive": True,
        "authenticated": False,
        "priority": "p0",
    },
    "maigret": {
        "title": "Maigret username discovery",
        "accepted_entity_types": ["username"],
        "passive": True,
        "authenticated": False,
        "priority": "p0",
    },
    "holehe": {
        "title": "Holehe service-presence signals",
        "accepted_entity_types": ["email"],
        "passive": True,
        "authenticated": False,
        "priority": "p0",
    },
    "blackbird": {
        "title": "Blackbird account discovery",
        "accepted_entity_types": ["username", "email"],
        "passive": True,
        "authenticated": False,
        "priority": "p1",
    },
    "theharvester": {
        "title": "theHarvester passive domain collection",
        "accepted_entity_types": ["domain"],
        "passive": True,
        "authenticated": False,
        "priority": "p1",
    },
    "subfinder": {
        "title": "Subfinder passive subdomain discovery",
        "accepted_entity_types": ["domain"],
        "passive": True,
        "authenticated": False,
        "priority": "p1",
    },
    "httpx": {
        "title": "HTTP metadata probe",
        "accepted_entity_types": ["domain", "hostname", "url"],
        "passive": False,
        "authenticated": False,
        "priority": "p2",
    },
    "ghunt": {
        "title": "GHunt public Google identity",
        "accepted_entity_types": ["email"],
        "passive": True,
        "authenticated": True,
        "priority": "p2",
    },
    "exiftool": {
        "title": "ExifTool metadata extraction",
        "accepted_entity_types": ["file"],
        "passive": True,
        "authenticated": False,
        "priority": "p1",
    },
    "tesseract": {
        "title": "Tesseract OCR indicators",
        "accepted_entity_types": ["file"],
        "passive": True,
        "authenticated": False,
        "priority": "p1",
    },
    "poppler": {
        "title": "Poppler PDF indicators",
        "accepted_entity_types": ["file"],
        "passive": True,
        "authenticated": False,
        "priority": "p1",
    },
}


def _redact_for_display(value: Any) -> Any:
    """Defensively redact credential-like fields before returning evidence."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            normalized = key_text.strip().lower()
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                output[key_text] = "<redacted>"
            else:
                output[key_text] = _redact_for_display(item)
        return output
    if isinstance(value, (list, tuple, set)):
        return [_redact_for_display(item) for item in value]
    if isinstance(value, str):
        cleaned = _QUERY_SECRET.sub(
            r"\1<redacted>",
            _BASIC_AUTH.sub(
                "Basic <redacted>",
                _BEARER.sub("Bearer <redacted>", value),
            ),
        )
        cleaned = _LONG_SECRET.sub(
            "<redacted-long-value>",
            cleaned,
        )
        return cleaned[:4000] + ("…<truncated>" if len(cleaned) > 4000 else "")
    return value


class InvestigationCreate(BaseModel):
    target_name: str = Field(min_length=1, max_length=255)
    target_aliases: list[str] = Field(default_factory=list, max_length=20)
    target_username: str | None = Field(default=None, max_length=64)
    additional_usernames: list[str] = Field(default_factory=list, max_length=20)
    target_email: str | None = Field(default=None, max_length=320)
    employer: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    authorized_domains: list[str] = Field(default_factory=list, max_length=20)
    authorized_ips: list[str] = Field(default_factory=list, max_length=20)
    allow_infrastructure_enrichment: bool = False
    allow_authenticated_transforms: bool = False
    compare_previous_cases: bool = False
    lawful_purpose: str = Field(min_length=8, max_length=500)
    authorization_reference: str = Field(min_length=3, max_length=200)
    authorization_expires_at: datetime
    authorization_confirmed: bool
    permitted_sources: list[str] = Field(min_length=1)
    depth: str = "surface"

    @field_validator("target_name", "lawful_purpose", "authorization_reference")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value cannot be empty")
        return cleaned

    @field_validator("target_username")
    @classmethod
    def validate_username(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        cleaned = value.strip()
        if not _USERNAME.fullmatch(cleaned):
            raise ValueError(
                "Username may contain only letters, numbers, dots, dashes, and underscores"
            )
        return cleaned

    @field_validator("additional_usernames")
    @classmethod
    def validate_additional_usernames(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            cleaned = value.strip()
            if not cleaned:
                continue
            if not _USERNAME.fullmatch(cleaned):
                raise ValueError(
                    "Additional usernames may contain only letters, numbers, "
                    "dots, dashes, and underscores"
                )
            normalized.append(cleaned)
        return list(dict.fromkeys(normalized))

    @field_validator("target_email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        cleaned = value.strip().lower()
        if not _EMAIL.fullmatch(cleaned):
            raise ValueError("Enter a valid email address")
        return cleaned

    @field_validator("permitted_sources")
    @classmethod
    def validate_sources(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip().lower() for value in values))
        normalized = [value for value in normalized if value]
        if not normalized:
            raise ValueError("Select at least one source")
        unsupported = set(normalized) - _ALLOWED_SOURCES
        if unsupported:
            raise ValueError(f"Unsupported sources: {sorted(unsupported)}")
        return normalized

    @field_validator("authorized_domains")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            domain = value.strip().lower().rstrip(".")
            if not domain:
                continue
            if (
                len(domain) > 253
                or "." not in domain
                or not all(
                    label
                    and len(label) <= 63
                    and label[0].isalnum()
                    and label[-1].isalnum()
                    and all(
                        character.isalnum() or character == "-" for character in label
                    )
                    for label in domain.split(".")
                )
            ):
                raise ValueError(f"Invalid authorized domain: {value}")
            if (
                domain in _RESERVED_OSINT_DOMAINS
                or any(domain.endswith(suffix) for suffix in _RESERVED_OSINT_SUFFIXES)
            ):
                raise ValueError(
                    f"Reserved demonstration domain cannot be used for OSINT: {value}"
                )
            normalized.append(domain)
        return list(dict.fromkeys(normalized))

    @field_validator("authorized_ips")
    @classmethod
    def validate_ips(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            try:
                normalized.append(str(ipaddress.ip_address(value.strip())))
            except ValueError as exc:
                raise ValueError(f"Invalid authorized IP address: {value}") from exc
        return list(dict.fromkeys(normalized))

    @field_validator("depth")
    @classmethod
    def validate_depth(cls, value: str) -> str:
        if value not in {"surface", "deep", "full"}:
            raise ValueError("Depth must be surface, deep, or full")
        return value

    @model_validator(mode="after")
    def validate_authorization(self) -> "InvestigationCreate":
        if not self.authorization_confirmed:
            raise ValueError("Written authorization must be confirmed")
        expiry = self.authorization_expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
            self.authorization_expires_at = expiry
        if expiry <= datetime.now(timezone.utc):
            raise ValueError("Authorization expiry must be in the future")
        if (
            not self.target_username
            and not self.additional_usernames
            and not self.target_email
        ):
            raise ValueError("Provide at least one username or email")
        if self.target_username:
            self.additional_usernames = [
                value
                for value in self.additional_usernames
                if value.casefold() != self.target_username.casefold()
            ]
        infrastructure_sources = {"shodan", "censys"} & set(self.permitted_sources)
        if infrastructure_sources and (
            not self.allow_infrastructure_enrichment or not self.authorized_ips
        ):
            raise ValueError(
                "Shodan and Censys require infrastructure consent and an authorized IP"
            )
        if infrastructure_sources:
            non_public_ips = [
                value
                for value in self.authorized_ips
                if not ipaddress.ip_address(value).is_global
            ]
            if non_public_ips:
                raise ValueError(
                    "Shodan and Censys accept only literal public IP addresses; "
                    f"non-public values: {non_public_ips}"
                )
        if "httpx" in self.permitted_sources and (
            not self.authorized_domains
            or not self.allow_infrastructure_enrichment
        ):
            raise ValueError(
                "httpx requires infrastructure consent and an authorized domain"
            )
        if (
            "ghunt" in self.permitted_sources
            and not self.allow_authenticated_transforms
        ):
            raise ValueError(
                "GHunt requires separate authenticated-transform consent"
            )
        return self


class TransformRequest(BaseModel):
    transform: str = Field(min_length=2, max_length=64)
    entity_type: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    pivot_depth: int = Field(default=0, ge=0, le=10)

    @field_validator("transform", "entity_type", "value")
    @classmethod
    def clean_transform_strings(cls, value: str) -> str:
        return value.strip()

    @field_validator("evidence_ids")
    @classmethod
    def unique_transform_evidence_ids(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    @model_validator(mode="after")
    def validate_transform_shape(self) -> "TransformRequest":
        name = self.transform.casefold()
        spec = _TRANSFORM_CATALOG.get(name)
        if spec is None:
            raise ValueError("Unknown transform")
        self.transform = name
        self.entity_type = self.entity_type.casefold()
        if self.entity_type not in spec["accepted_entity_types"]:
            raise ValueError(
                f"{name} does not accept entity type {self.entity_type}"
            )
        return self


class GraphLayoutNode(BaseModel):
    id: str = Field(min_length=1, max_length=160)
    x: float = Field(ge=-100000, le=100000)
    y: float = Field(ge=-100000, le=100000)
    collapsed: bool = False


class GraphLayoutUpdate(BaseModel):
    nodes: list[GraphLayoutNode] = Field(max_length=3000)
    viewport: dict[str, float] = Field(default_factory=dict)

    @field_validator("viewport")
    @classmethod
    def validate_viewport(cls, value: dict[str, float]) -> dict[str, float]:
        allowed = {"x", "y", "zoom"}
        if set(value) - allowed:
            raise ValueError("Unsupported viewport field")
        output = {}
        for key, member in value.items():
            number = float(member)
            if not -100000 <= number <= 100000:
                raise ValueError("Viewport value is outside the supported range")
            output[key] = number
        return output


def _database_url() -> str:
    explicit = os.getenv("DB_URL")
    if explicit:
        return explicit
    password = quote_plus(os.getenv("DB_PASSWORD", "changeme"))
    return f"postgresql+asyncpg://deepvault:{password}@postgres:5432/deepvault"


engine = create_async_engine(_database_url(), pool_pre_ping=True)
sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
celery = Celery(
    "deepvault-dashboard",
    broker=os.getenv("CELERY_BROKER", "redis://redis:6379/0"),
)
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="DeepVault",
    description="Local authorized person-OSINT dashboard",
    version="0.2.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def protect_local_responses(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _status_value(status: InvestigationStatus | str) -> str:
    return status.value if isinstance(status, InvestigationStatus) else str(status)


async def _artifact_count(session: AsyncSession, investigation_id: UUID) -> int:
    return int(
        await session.scalar(
            select(func.count(Artifact.id)).where(
                Artifact.investigation_id == investigation_id
            )
        )
        or 0
    )


async def _evidence_preview(
    session: AsyncSession, investigation_id: UUID
) -> list[dict[str, Any]]:
    artifacts = (
        await session.scalars(
            select(Artifact)
            .where(Artifact.investigation_id == investigation_id)
            .order_by(Artifact.first_seen.desc())
            .limit(50)
        )
    ).all()
    preview = []
    for artifact in artifacts:
        context = _redact_for_display(artifact.context or {})
        evidence = context.get("evidence")
        normalized = evidence if isinstance(evidence, dict) else {}
        evidence_id = normalized.get("id") or str(artifact.id)
        preview.append(
            {
                "id": evidence_id,
                "source": normalized.get("source") or artifact.source,
                "type": normalized.get("type") or artifact.source_type,
                "value": normalized.get("value")
                or _redact_for_display(artifact.identifier_value),
                "source_url": normalized.get("source_url"),
                "confidence": normalized.get("confidence")
                if normalized.get("confidence") is not None
                else artifact.confidence,
                "reliability": normalized.get("reliability"),
                "identity_status": normalized.get("identity_status"),
                "observed_at": normalized.get("observed_at") or artifact.first_seen,
                "notes": normalized.get("notes", []),
                "metadata": normalized.get("metadata", context),
            }
        )
    return preview


async def _serialize(
    session: AsyncSession,
    investigation: Investigation,
    *,
    include_report: bool = False,
) -> dict[str, Any]:
    metadata = investigation.case_metadata or {}
    stored_report = metadata.get("structured_report")
    report = (
        _redact_for_display(stored_report) if isinstance(stored_report, dict) else None
    )
    output: dict[str, Any] = {
        "id": str(investigation.id),
        "target_name": investigation.target_name,
        "target_username": investigation.target_username,
        "additional_usernames": metadata.get("additional_usernames", []),
        "target_email": investigation.target_email,
        "status": _status_value(investigation.status),
        "depth": investigation.depth,
        "risk_score": investigation.risk_score,
        "created_at": investigation.created_at,
        "updated_at": investigation.updated_at,
        "completed_at": investigation.completed_at,
        "authorization_reference": metadata.get("authorization_reference"),
        "permitted_sources": metadata.get("permitted_sources", []),
        "authorized_domains": metadata.get("authorized_domains", []),
        "allow_authenticated_transforms": bool(
            metadata.get("allow_authenticated_transforms")
        ),
        "transform_runs": _redact_for_display(metadata.get("transform_runs", [])),
        "compare_previous_cases": bool(metadata.get("compare_previous_cases")),
        "source_status": metadata.get("source_status", []),
        "artifact_count": await _artifact_count(session, investigation.id),
        "has_report": report is not None,
        "progress": metadata.get("progress")
        or {
            "stage": _status_value(investigation.status),
            "message": "Waiting for an available worker",
            "percent": 0,
        },
        "error": metadata.get("error"),
    }
    if include_report:
        output["report"] = report
        output["evidence_preview"] = await _evidence_preview(session, investigation.id)
    return output


async def _get_investigation(
    session: AsyncSession, investigation_id: UUID
) -> Investigation:
    investigation = await session.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation


def _stored_graph(investigation: Investigation) -> dict[str, Any]:
    report = (investigation.case_metadata or {}).get("structured_report")
    graph = report.get("identity_graph") if isinstance(report, dict) else None
    if not isinstance(graph, dict):
        raise HTTPException(status_code=409, detail="Identity graph is not ready")
    return _redact_for_display(graph)


def _graph_parts(
    investigation: Investigation,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    """Return a validated graph and its evidence index for public export."""
    graph = _stored_graph(investigation)
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    evidence = graph.get("evidence_index", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise HTTPException(status_code=409, detail="Identity graph is malformed")
    clean_nodes = [node for node in nodes if isinstance(node, dict)]
    clean_edges = [edge for edge in edges if isinstance(edge, dict)]
    evidence_items = [item for item in evidence if isinstance(item, dict)]
    report = (investigation.case_metadata or {}).get("structured_report")
    ledger = report.get("evidence_ledger", []) if isinstance(report, dict) else []
    if isinstance(ledger, list):
        evidence_items.extend(item for item in ledger if isinstance(item, dict))
    node_ids = {
        str(node.get("id"))
        for node in clean_nodes
        if node.get("id")
    }
    edge_ids = {
        str(edge.get("id"))
        for edge in clean_edges
        if edge.get("id")
    }
    evidence_index: dict[str, dict[str, Any]] = {}
    for item in evidence_items:
        if item.get("id"):
            evidence_index[str(item["id"])] = item
    if len(node_ids) != len(clean_nodes):
        raise HTTPException(
            status_code=409,
            detail="Identity graph contains missing or duplicate node IDs",
        )
    if len(edge_ids) != len(clean_edges):
        raise HTTPException(
            status_code=409,
            detail="Identity graph contains missing or duplicate relationship IDs",
        )
    for node in clean_nodes:
        cited = {str(value) for value in node.get("evidence_ids", [])}
        if cited - set(evidence_index):
            raise HTTPException(
                status_code=409,
                detail="Identity graph node cites unknown evidence",
            )
    for edge in clean_edges:
        endpoints = {
            str(edge.get("source_node_id")),
            str(edge.get("target_node_id")),
        }
        cited = {str(value) for value in edge.get("evidence_ids", [])}
        if endpoints - node_ids or not cited or cited - set(evidence_index):
            raise HTTPException(
                status_code=409,
                detail="Identity graph relationship failed evidence validation",
            )
    return graph, clean_nodes, clean_edges, evidence_index


_IDENTITY_STATUS_ORDER = {
    "unrelated": -1,
    "insufficient_evidence": 0,
    "possible": 1,
    "probable": 2,
    "highly_probable": 3,
    "confirmed": 4,
}

_PLAIN_RELATIONSHIP_LABELS = {
    "candidate_profile": "Possible public profile",
    "candidate_observation": "Possible public observation",
    "publishes_attribute": "Discovery tool returned this result",
    "breach_association": "Breach metadata references this identifier",
    "service_registration": "Service registration signal",
}


def _is_generic_profile_endpoint(value: Any) -> bool:
    """Identify search/home endpoints that cannot represent a person profile."""
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold().removeprefix("www.")
    path = (parsed.path or "/").rstrip("/") or "/"
    return (
        (host == "discord.com" and path == "/")
        or (host == "scholar.google.com" and path.casefold() == "/scholar")
        or (host == "op.gg" and path.casefold() == "/lol/summoners/search")
    )


def _entity_review_details(
    *,
    entity: dict[str, Any],
    publisher_count: int,
) -> dict[str, Any]:
    """Translate technical confidence into a conservative review instruction."""
    metadata = entity.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    quality_status = str(metadata.get("verification_status") or "unverified")
    identity_status = str(
        entity.get("identity_status") or "insufficient_evidence"
    )
    entity_type = str(entity.get("entity_type") or "public_observation")
    confidence = float(entity.get("confidence") or 0)
    generic_endpoint = _is_generic_profile_endpoint(
        entity.get("canonical_value") or entity.get("label")
    )
    sensitive = bool(metadata.get("sensitive")) or quality_status == "quarantined"
    suppressed = quality_status in {"rejected", "quarantined"} or generic_endpoint

    if entity_type == "authorized_target":
        priority = "target"
        confidence_label = "Authorized target"
        explanation = (
            "This node contains the identifiers supplied in the authorized case "
            "scope; it is not a collected identity claim."
        )
    elif entity_type == "public_source":
        priority = "publisher"
        confidence_label = "Evidence publisher"
        explanation = (
            "This technical node records which discovery tool published cited "
            "observations."
        )
    elif suppressed:
        priority = "suppressed"
        confidence_label = "Hidden by default"
        if sensitive:
            explanation = (
                "Sensitive-site username similarity is quarantined. It must not "
                "be attributed to the person without separate, strong evidence."
            )
        elif generic_endpoint:
            explanation = (
                "This is a generic home or search page, not a person-specific "
                "profile, so it is hidden from the simplified graph."
            )
        else:
            explanation = (
                "The quality gate identified a non-profile endpoint, so this "
                "observation is hidden from the simplified graph."
            )
    elif identity_status in {"confirmed", "highly_probable", "probable"}:
        priority = "supported"
        confidence_label = {
            "confirmed": "Confirmed",
            "highly_probable": "Strongly supported",
            "probable": "Probable",
        }[identity_status]
        explanation = (
            "The cited evidence supports this identity association. Review the "
            "evidence IDs before relying on it."
        )
    elif identity_status == "possible":
        priority = "review_first"
        confidence_label = "Possible match"
        explanation = (
            "This candidate has some identity support but still needs manual "
            "verification against public profile details."
        )
    elif entity_type == "service":
        priority = "review_first"
        confidence_label = "Service signal"
        explanation = (
            "A public service-registration check returned a signal. It does not "
            "prove account access, current ownership, or activity."
        )
    elif publisher_count > 1:
        priority = "review_first"
        confidence_label = "Check first"
        explanation = (
            "More than one discovery tool returned this public page. Those tools "
            "may share username catalogues, so the overlap prioritizes review but "
            "does not independently prove ownership."
        )
    else:
        priority = "low_signal"
        confidence_label = "Unverified lead"
        explanation = (
            "One discovery tool returned a page matching the supplied username. "
            "Compare public profile details before attributing it to the person."
        )
    return {
        "review_priority": priority,
        "confidence_label": confidence_label,
        "plain_language_explanation": explanation,
        "quality_status": quality_status,
        "publisher_count": publisher_count,
        "sensitive": sensitive,
        "generic_endpoint": generic_endpoint,
        "technical_confidence": confidence,
    }


def _review_summary(
    *,
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    target_entity_id: Any,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Build a cited, non-technical assessment over the normalized graph."""
    candidates = [
        entity
        for entity in entities
        if entity.get("entity_id") != target_entity_id
        and entity.get("entity_type")
        not in {"authorized_target", "public_source"}
    ]
    supported = [
        entity
        for entity in candidates
        if entity.get("review_priority") == "supported"
    ]
    review_first = [
        entity
        for entity in candidates
        if entity.get("review_priority") == "review_first"
    ]
    low_signal = [
        entity
        for entity in candidates
        if entity.get("review_priority") == "low_signal"
    ]
    suppressed = [
        entity
        for entity in candidates
        if entity.get("review_priority") == "suppressed"
    ]
    cited_ids = sorted(
        {
            evidence_id
            for entity in candidates
            for evidence_id in entity.get("evidence_ids", [])
        }
    )

    if supported:
        verdict_status = "supported_matches"
        verdict_title = "Supported identity matches require analyst review"
        verdict_explanation = (
            f"{len(supported)} candidate"
            f"{'s' if len(supported) != 1 else ''} reached probable or stronger "
            "identity support. Confirm the cited public evidence before use."
        )
    elif review_first:
        verdict_status = "manual_verification_required"
        verdict_title = "No verified identity match yet"
        verdict_explanation = (
            f"{len(review_first)} candidate"
            f"{'s' if len(review_first) != 1 else ''} should be checked first, "
            "but none is safe to attribute to the person automatically."
        )
    else:
        verdict_status = "no_verified_identity_match"
        verdict_title = "No verified identity match"
        verdict_explanation = (
            "The collected observations are low-signal leads. More public "
            "identity attributes or independent sources are needed."
        )

    priority_rank = {"supported": 0, "review_first": 1, "low_signal": 2}
    priority_leads = sorted(
        [entity for entity in candidates if entity not in suppressed],
        key=lambda entity: (
            priority_rank.get(str(entity.get("review_priority")), 9),
            -int(entity.get("publisher_count") or 0),
            -float(entity.get("confidence") or 0),
            str(entity.get("label") or "").casefold(),
        ),
    )[:12]
    priority_leads = [
        {
            "entity_id": entity.get("entity_id"),
            "entity_type": entity.get("entity_type"),
            "label": entity.get("label"),
            "public_url": (
                entity.get("canonical_value")
                if isinstance(entity.get("canonical_value"), str)
                and str(entity.get("canonical_value")).startswith(
                    ("http://", "https://")
                )
                else None
            ),
            "review_priority": entity.get("review_priority"),
            "confidence_label": entity.get("confidence_label"),
            "technical_confidence": entity.get("confidence"),
            "source_tools": entity.get("source_tools", []),
            "publisher_count": entity.get("publisher_count", 0),
            "explanation": entity.get("plain_language_explanation"),
            "evidence_ids": entity.get("evidence_ids", []),
        }
        for entity in priority_leads
    ]

    overlap = [
        entity
        for entity in candidates
        if int(entity.get("publisher_count") or 0) > 1
        and entity.get("review_priority") != "suppressed"
    ]
    service_signals = [
        entity
        for entity in candidates
        if entity.get("entity_type") == "service"
        and entity.get("review_priority") != "suppressed"
    ]
    key_points = [
        {
            "title": "Candidate observations",
            "statement": (
                f"{len(candidates)} public observations were retained; "
                f"{len(supported)} reached probable or stronger identity support."
            ),
            "evidence_ids": cited_ids,
        }
    ]
    if overlap:
        key_points.append(
            {
                "title": "Cross-tool overlap",
                "statement": (
                    f"{len(overlap)} public page"
                    f"{'s were' if len(overlap) != 1 else ' was'} returned by "
                    "more than one discovery tool. Catalogue overlap makes these "
                    "review priorities, not verified identities."
                ),
                "evidence_ids": sorted(
                    {
                        evidence_id
                        for entity in overlap
                        for evidence_id in entity.get("evidence_ids", [])
                    }
                ),
            }
        )
    if service_signals:
        key_points.append(
            {
                "title": "Service-registration signals",
                "statement": (
                    f"{len(service_signals)} public service signal"
                    f"{'s were' if len(service_signals) != 1 else ' was'} "
                    "returned. A signal does not prove access or current ownership."
                ),
                "evidence_ids": sorted(
                    {
                        evidence_id
                        for entity in service_signals
                        for evidence_id in entity.get("evidence_ids", [])
                    }
                ),
            }
        )

    coverage = report.get("source_coverage", [])
    coverage = coverage if isinstance(coverage, list) else []
    coverage_groups: dict[str, list[dict[str, Any]]] = {
        "observed": [],
        "no_results": [],
        "unavailable": [],
        "not_run": [],
    }
    for item in coverage:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "not_run").casefold()
        evidence_count = int(item.get("evidence_count") or 0)
        if evidence_count:
            group = "observed"
        elif status in {"unavailable", "not_configured", "missing_configuration"}:
            group = "unavailable"
        elif status in {"no_results", "no_result", "covered_no_results"}:
            group = "no_results"
        else:
            group = "not_run"
        coverage_groups[group].append(
            {
                "source": item.get("source"),
                "status": item.get("status"),
                "evidence_count": evidence_count,
                "reason": item.get("reason"),
            }
        )

    return {
        "verdict": {
            "status": verdict_status,
            "title": verdict_title,
            "explanation": verdict_explanation,
            "evidence_ids": cited_ids,
        },
        "counts": {
            "candidate_observations": len(candidates),
            "supported": len(supported),
            "review_first": len(review_first),
            "low_signal": len(low_signal),
            "suppressed": len(suppressed),
            "relationships": len(relationships),
        },
        "priority_leads": priority_leads,
        "key_points": key_points,
        "coverage": coverage_groups,
        "cautions": [
            {
                "statement": (
                    "A matching username or public page does not by itself prove "
                    "that the investigated person owns the account."
                ),
                "evidence_ids": cited_ids,
            },
            {
                "statement": (
                    "Agreement between username discovery tools may come from "
                    "shared site catalogues and is not independent identity proof."
                ),
                "evidence_ids": sorted(
                    {
                        evidence_id
                        for entity in overlap
                        for evidence_id in entity.get("evidence_ids", [])
                    }
                ),
            },
        ],
    }


def _normalized_graph_view(
    investigation: Investigation,
    graph: dict[str, Any],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    evidence_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Create a UI-friendly entity model without weakening graph provenance."""
    metadata = investigation.case_metadata or {}
    report = metadata.get("structured_report")
    report = report if isinstance(report, dict) else {}
    ledger = report.get("evidence_ledger", [])
    ledger_by_id = {
        str(item.get("id")): item
        for item in ledger
        if isinstance(item, dict) and item.get("id")
    } if isinstance(ledger, list) else {}
    hypotheses = graph.get("hypotheses", [])
    hypothesis_by_node = {
        str(item.get("object_node_id")): item
        for item in hypotheses
        if isinstance(item, dict) and item.get("object_node_id")
    } if isinstance(hypotheses, list) else {}
    edges_by_node: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        for node_id in (edge.get("source_node_id"), edge.get("target_node_id")):
            if node_id:
                edges_by_node.setdefault(str(node_id), []).append(edge)

    entities: list[dict[str, Any]] = []
    cluster_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for node in nodes:
        node_id = str(node["id"])
        kind = str(node.get("kind") or "public_observation")
        evidence_ids = [str(value) for value in node.get("evidence_ids", [])]
        evidence_items = [
            ledger_by_id.get(value) or evidence_index.get(value, {})
            for value in evidence_ids
        ]
        sources = sorted(
            {
                str(item.get("source"))
                for item in evidence_items
                if item.get("source")
            }
            | {
                str(step.get("source"))
                for edge in edges_by_node.get(node_id, [])
                for step in edge.get("provenance_chain", [])
                if isinstance(step, dict) and step.get("source")
            },
            key=str.casefold,
        )
        for source in sources:
            source_counts[source] = source_counts.get(source, 0) + 1
        observed = sorted(
            str(item.get("observed_at"))
            for item in evidence_items
            if item.get("observed_at")
        )
        attributes = node.get("attributes")
        attributes = attributes if isinstance(attributes, dict) else {}
        hypothesis = hypothesis_by_node.get(node_id, {})
        confidence = hypothesis.get("confidence")
        identity_status = hypothesis.get("identity_status")
        related_edges = edges_by_node.get(node_id, [])
        if confidence is None and related_edges:
            confidence = max(
                float(edge.get("confidence") or 0)
                for edge in related_edges
            )
            identity_status = max(
                (
                    str(edge.get("identity_status") or "insufficient_evidence")
                    for edge in related_edges
                ),
                key=lambda status: _IDENTITY_STATUS_ORDER.get(status, 0),
            )
        if (
            node_id == graph.get("target_node_id")
            or kind == "authorized_target"
        ):
            confidence = 1.0
            identity_status = "authorized_target"
        cluster_counts[kind] = cluster_counts.get(kind, 0) + 1
        entity = {
            "entity_id": node_id,
            "entity_type": kind,
            "label": node.get("label") or node_id,
            "canonical_value": (
                attributes.get("url")
                or attributes.get("email")
                or attributes.get("address")
                or node.get("label")
            ),
            "aliases": attributes.get("aliases", []),
            "source_tools": sources,
            "source_urls": sorted(
                {
                    str(item.get("source_url"))
                    for item in evidence_items
                    if item.get("source_url")
                }
            ),
            "confidence": confidence,
            "identity_status": identity_status or "insufficient_evidence",
            "first_seen": observed[0] if observed else None,
            "last_seen": observed[-1] if observed else None,
            "metadata": attributes,
            "evidence_ids": evidence_ids,
        }
        entity.update(
            _entity_review_details(
                entity=entity,
                publisher_count=len(sources),
            )
        )
        entities.append(entity)

    relationships = [
        {
            "edge_id": str(edge["id"]),
            "from_entity_id": edge.get("source_node_id"),
            "to_entity_id": edge.get("target_node_id"),
            "relationship_type": edge.get("relationship"),
            "plain_language_type": _PLAIN_RELATIONSHIP_LABELS.get(
                str(edge.get("relationship")),
                str(edge.get("relationship") or "Cited relationship").replace(
                    "_", " "
                ).capitalize(),
            ),
            "confidence": edge.get("confidence"),
            "identity_status": edge.get("identity_status"),
            "source_tools": sorted(
                {
                    str(step.get("source"))
                    for step in edge.get("provenance_chain", [])
                    if isinstance(step, dict) and step.get("source")
                },
                key=str.casefold,
            ),
            "evidence_ids": [str(value) for value in edge.get("evidence_ids", [])],
            "reason": edge.get("explanation")
            or next(
                (
                    step.get("explanation")
                    for step in edge.get("provenance_chain", [])
                    if isinstance(step, dict) and step.get("explanation")
                ),
                "Cited evidence relationship.",
            ),
            "independent_source_count": edge.get("independent_source_count", 1),
            "provenance_chain": edge.get("provenance_chain", []),
        }
        for edge in edges
    ]
    normalized = {
        "target_entity_id": graph.get("target_node_id"),
        "entities": entities,
        "relationships": relationships,
        "clusters": [
            {"entity_type": kind, "count": count}
            for kind, count in sorted(cluster_counts.items())
        ],
        "stats": {
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "evidence_count": len(evidence_index),
            "source_count": len(source_counts),
            "entities_by_type": dict(sorted(cluster_counts.items())),
            "entities_by_source": dict(sorted(source_counts.items())),
        },
    }
    normalized["review_summary"] = _review_summary(
        entities=entities,
        relationships=relationships,
        target_entity_id=graph.get("target_node_id"),
        report=report,
    )
    return normalized


def _graph_document(investigation: Investigation) -> dict[str, Any]:
    metadata = investigation.case_metadata or {}
    graph, nodes, edges, evidence_index = _graph_parts(investigation)
    permitted = {
        str(source).casefold()
        for source in metadata.get("permitted_sources", [])
    }
    transforms = [
        {"name": name, **spec}
        for name, spec in sorted(_TRANSFORM_CATALOG.items())
        if name in permitted
    ]
    return {
        "schemaVersion": 2,
        "caseId": str(investigation.id),
        "authorizationReference": metadata.get("authorization_reference"),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "graph": graph,
        "layout": _redact_for_display(metadata.get("graph_layout", {})),
        "transforms": transforms,
        "transformRuns": _redact_for_display(metadata.get("transform_runs", [])),
        **_normalized_graph_view(
            investigation,
            graph,
            nodes,
            edges,
            evidence_index,
        ),
    }


def _graphml_document(investigation: Investigation) -> bytes:
    graph, nodes, edges, _ = _graph_parts(investigation)
    namespace = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", namespace)
    root = ET.Element(f"{{{namespace}}}graphml")
    for key_id, target, name, attr_type in (
        ("n_label", "node", "label", "string"),
        ("n_type", "node", "entity_type", "string"),
        ("n_evidence", "node", "evidence_ids", "string"),
        ("n_attributes", "node", "attributes", "string"),
        ("e_type", "edge", "relationship_type", "string"),
        ("e_confidence", "edge", "confidence", "double"),
        ("e_status", "edge", "identity_status", "string"),
        ("e_reason", "edge", "reason", "string"),
        ("e_evidence", "edge", "evidence_ids", "string"),
    ):
        ET.SubElement(
            root,
            f"{{{namespace}}}key",
            {
                "id": key_id,
                "for": target,
                "attr.name": name,
                "attr.type": attr_type,
            },
        )
    graph_element = ET.SubElement(
        root,
        f"{{{namespace}}}graph",
        {
            "id": str(investigation.id),
            "edgedefault": "directed",
        },
    )

    def add_data(parent: ET.Element, key: str, value: Any) -> None:
        child = ET.SubElement(parent, f"{{{namespace}}}data", {"key": key})
        child.text = str(value)

    for node in nodes:
        element = ET.SubElement(
            graph_element,
            f"{{{namespace}}}node",
            {"id": str(node["id"])},
        )
        add_data(element, "n_label", node.get("label") or node["id"])
        add_data(element, "n_type", node.get("kind") or "public_observation")
        add_data(element, "n_evidence", json.dumps(node.get("evidence_ids", [])))
        add_data(
            element,
            "n_attributes",
            json.dumps(node.get("attributes", {}), sort_keys=True),
        )
    for edge in edges:
        element = ET.SubElement(
            graph_element,
            f"{{{namespace}}}edge",
            {
                "id": str(edge["id"]),
                "source": str(edge["source_node_id"]),
                "target": str(edge["target_node_id"]),
            },
        )
        add_data(element, "e_type", edge.get("relationship") or "related_to")
        add_data(element, "e_confidence", edge.get("confidence", 0))
        add_data(
            element,
            "e_status",
            edge.get("identity_status") or "insufficient_evidence",
        )
        add_data(element, "e_reason", edge.get("explanation") or "")
        add_data(element, "e_evidence", json.dumps(edge.get("evidence_ids", [])))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _gexf_document(investigation: Investigation) -> bytes:
    _, nodes, edges, _ = _graph_parts(investigation)
    namespace = "http://www.gexf.net/1.3"
    ET.register_namespace("", namespace)
    root = ET.Element(
        f"{{{namespace}}}gexf",
        {"version": "1.3"},
    )
    graph_element = ET.SubElement(
        root,
        f"{{{namespace}}}graph",
        {"defaultedgetype": "directed", "mode": "static"},
    )
    nodes_element = ET.SubElement(graph_element, f"{{{namespace}}}nodes")
    for node in nodes:
        ET.SubElement(
            nodes_element,
            f"{{{namespace}}}node",
            {
                "id": str(node["id"]),
                "label": str(node.get("label") or node["id"]),
            },
        )
    edges_element = ET.SubElement(graph_element, f"{{{namespace}}}edges")
    for edge in edges:
        ET.SubElement(
            edges_element,
            f"{{{namespace}}}edge",
            {
                "id": str(edge["id"]),
                "source": str(edge["source_node_id"]),
                "target": str(edge["target_node_id"]),
                "label": str(edge.get("relationship") or "related_to"),
                "weight": str(edge.get("confidence", 0)),
            },
        )
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _graph_csv_document(investigation: Investigation) -> str:
    document = _graph_document(investigation)
    entities = document.get("entities", [])
    relationships = document.get("relationships", [])
    review_summary = document.get("review_summary", {})

    def csv_safe(value: Any) -> Any:
        """Prevent spreadsheet formula execution without changing audit values."""
        if not isinstance(value, str):
            return value
        return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        (
            "record_type",
            "id",
            "entity_type",
            "label",
            "source_entity_id",
            "target_entity_id",
            "relationship_type",
            "confidence",
            "identity_status",
            "evidence_ids",
            "reason",
            "review_priority",
            "review_label",
            "source_tools",
            "publisher_count",
            "hidden_by_default",
            "plain_language",
        )
    )
    verdict = review_summary.get("verdict", {})
    if isinstance(verdict, dict) and verdict:
        writer.writerow(
            (
                "summary",
                "verdict",
                "",
                csv_safe(verdict.get("title")),
                "",
                "",
                "",
                "",
                verdict.get("status"),
                "|".join(str(value) for value in verdict.get("evidence_ids", [])),
                csv_safe(verdict.get("explanation")),
                verdict.get("status"),
                csv_safe(verdict.get("title")),
                "",
                "",
                "false",
                csv_safe(verdict.get("explanation")),
            )
        )
    for entity in entities:
        writer.writerow(
            (
                "entity",
                entity.get("entity_id"),
                entity.get("entity_type"),
                csv_safe(entity.get("label")),
                "",
                "",
                "",
                entity.get("confidence"),
                entity.get("identity_status"),
                "|".join(
                    str(value) for value in entity.get("evidence_ids", [])
                ),
                csv_safe(entity.get("plain_language_explanation")),
                entity.get("review_priority"),
                csv_safe(entity.get("confidence_label")),
                "|".join(
                    csv_safe(str(value))
                    for value in entity.get("source_tools", [])
                ),
                entity.get("publisher_count"),
                str(entity.get("review_priority") == "suppressed").casefold(),
                csv_safe(entity.get("plain_language_explanation")),
            )
        )
    for relationship in relationships:
        writer.writerow(
            (
                "relationship",
                relationship.get("edge_id"),
                "",
                "",
                relationship.get("from_entity_id"),
                relationship.get("to_entity_id"),
                relationship.get("relationship_type"),
                relationship.get("confidence"),
                relationship.get("identity_status"),
                "|".join(
                    str(value)
                    for value in relationship.get("evidence_ids", [])
                ),
                csv_safe(relationship.get("reason")),
                "",
                csv_safe(relationship.get("plain_language_type")),
                "|".join(
                    csv_safe(str(value))
                    for value in relationship.get("source_tools", [])
                ),
                "",
                "false",
                csv_safe(relationship.get("reason")),
            )
        )
    return output.getvalue()


def _node_mapping_type(node: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(node.get("kind") or "custom")
    label = str(node.get("label") or node.get("id") or "Observation")
    attributes = node.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    if kind == "authorized_target":
        return "name", {"fullName": label}
    if kind == "email_observation":
        value = attributes.get("email") or attributes.get("address")
        return "email", {"address": value or label}
    if kind == "phone_observation":
        return "phone", {"number": attributes.get("phone") or label}
    if kind == "username_observation":
        return "custom", {"title": "Username", "value": label}
    if kind == "public_profile":
        url = label if label.startswith(("http://", "https://")) else attributes.get("url")
        hostname = ""
        if isinstance(url, str):
            try:
                hostname = (urlsplit(url).hostname or "").casefold()
            except ValueError:
                hostname = ""
        platform = next(
            (
                name
                for name, domains in {
                    "instagram": ("instagram.com",),
                    "facebook": ("facebook.com",),
                    "twitter": ("twitter.com", "x.com"),
                    "youtube": ("youtube.com",),
                    "tiktok": ("tiktok.com",),
                    "linkedin": ("linkedin.com",),
                    "reddit": ("reddit.com",),
                    "telegram": ("t.me", "telegram.me"),
                }.items()
                if any(
                    hostname == domain or hostname.endswith(f".{domain}")
                    for domain in domains
                )
            ),
            "custom",
        )
        if platform == "custom":
            return "custom", {"title": hostname or "Public profile", "url": url}
        primary = {
            "youtube": "channelName",
            "linkedin": "fullName",
        }.get(platform, "username")
        return platform, {
            primary: (
                attributes.get("login")
                or attributes.get("display_name")
                or label
            ),
            "profileUrl": url,
        }
    return "custom", {
        "title": kind.replace("_", " ").title(),
        "value": label,
        "url": label if label.startswith(("http://", "https://")) else None,
    }


def _mapping_document(investigation: Investigation) -> dict[str, Any]:
    metadata = investigation.case_metadata or {}
    report = metadata.get("structured_report")
    report = report if isinstance(report, dict) else {}
    graph = _stored_graph(investigation)
    nodes = graph.get("nodes", [])
    nodes = nodes if isinstance(nodes, list) else []
    edges = graph.get("edges", [])
    edges = edges if isinstance(edges, list) else []
    layout = metadata.get("graph_layout")
    layout = layout if isinstance(layout, dict) else {}
    layout_nodes = layout.get("nodes", [])
    positions = {
        str(item.get("id")): {
            "x": item.get("x", 0),
            "y": item.get("y", 0),
        }
        for item in layout_nodes
        if isinstance(item, dict) and item.get("id")
    } if isinstance(layout_nodes, list) else {}
    evidence_ledger = report.get("evidence_ledger", [])
    evidence_index = {
        str(item.get("id")): item
        for item in evidence_ledger
        if isinstance(item, dict) and item.get("id")
    } if isinstance(evidence_ledger, list) else {}

    identifiers = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or not node.get("id"):
            continue
        node_id = str(node["id"])
        evidence_ids = [
            str(value)
            for value in node.get("evidence_ids", [])
            if str(value) in evidence_index
        ]
        evidence_items = [evidence_index[value] for value in evidence_ids]
        sources = sorted(
            {
                str(item.get("source"))
                for item in evidence_items
                if item.get("source")
            }
        )
        observed = sorted(
            str(item.get("observed_at"))
            for item in evidence_items
            if item.get("observed_at")
        )
        confidence_values = [
            float(item["confidence"])
            for item in evidence_items
            if isinstance(item.get("confidence"), (int, float))
        ]
        statuses = [
            str(item.get("identity_status"))
            for item in evidence_items
            if item.get("identity_status")
        ]
        identity_status = next(
            (
                status
                for status in (
                    "unrelated",
                    "insufficient_evidence",
                    "possible",
                    "probable",
                    "highly_probable",
                    "confirmed",
                )
                if status in statuses
            ),
            None,
        )
        independence_groups = {
            str(item.get("independence_group") or item.get("source"))
            for item in evidence_items
            if item.get("independence_group") or item.get("source")
        }
        identifier_type, fields = _node_mapping_type(node)
        identifiers.append(
            {
                "id": node_id,
                "type": identifier_type,
                "fields": {
                    key: value
                    for key, value in fields.items()
                    if value is not None
                },
                "notes": "Evidence-backed DeepVault graph node.",
                "position": positions.get(
                    node_id,
                    {
                        "x": 60 + (index % 4) * 260,
                        "y": 60 + (index // 4) * 170,
                    },
                ),
                "customIconId": None,
                "evidenceIds": evidence_ids,
                "sources": sources,
                "confidence": (
                    max(confidence_values) if confidence_values else None
                ),
                "identityStatus": identity_status,
                "independentSourceCount": len(independence_groups),
                "provenanceChain": [
                    {
                        "evidenceId": str(item.get("id")),
                        "source": item.get("source"),
                        "observedAt": item.get("observed_at"),
                        "independenceGroup": item.get("independence_group"),
                    }
                    for item in evidence_items
                ],
                "firstObserved": observed[0] if observed else None,
                "lastObserved": observed[-1] if observed else None,
                "entityKind": node.get("kind"),
                "attributes": node.get("attributes", {}),
            }
        )

    connections = []
    for edge in edges:
        if not isinstance(edge, dict) or not edge.get("id"):
            continue
        edge_evidence = [
            evidence_index[str(value)]
            for value in edge.get("evidence_ids", [])
            if str(value) in evidence_index
        ]
        observed = sorted(
            str(item.get("observed_at"))
            for item in edge_evidence
            if item.get("observed_at")
        )
        connections.append(
            {
                "id": str(edge["id"]),
                "source": edge.get("source_node_id"),
                "target": edge.get("target_node_id"),
                "sourceHandle": None,
                "targetHandle": None,
                "label": edge.get("relationship", ""),
                "relationship": edge.get("relationship"),
                "confidence": edge.get("confidence"),
                "identityStatus": edge.get("identity_status"),
                "evidenceIds": edge.get("evidence_ids", []),
                "sources": sorted(
                    {
                        str(step.get("source"))
                        for step in edge.get("provenance_chain", [])
                        if isinstance(step, dict) and step.get("source")
                    }
                ),
                "independentSourceCount": edge.get("independent_source_count", 1),
                "provenanceChain": edge.get("provenance_chain", []),
                "firstObserved": observed[0] if observed else None,
                "lastObserved": observed[-1] if observed else None,
            }
        )

    now = datetime.now(timezone.utc).isoformat()
    return {
        "schemaVersion": 2,
        "id": str(investigation.id),
        "name": f"DeepVault — {investigation.target_name}",
        "createdAt": (
            investigation.created_at.isoformat()
            if investigation.created_at
            else now
        ),
        "updatedAt": now,
        "target": {
            "name": investigation.target_name,
            "notes": (
                "Imported from an authorized DeepVault case. Every derived "
                "relationship retains its evidence IDs."
            ),
        },
        "identifiers": identifiers,
        "connections": connections,
        "locations": [],
        "pinLinks": [],
        "mapDisplay": {
            "showPinConnections": False,
            "pinConnectionColor": "#ef4444",
        },
        "caseContext": {
            "authorizationReference": metadata.get("authorization_reference"),
            "permittedSources": metadata.get("permitted_sources", []),
        },
    }


def _require_transform_authorization(
    investigation: Investigation,
    payload: TransformRequest,
) -> None:
    if investigation.status != InvestigationStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail="Transforms require a completed investigation",
        )
    metadata = investigation.case_metadata or {}
    if not metadata.get("authorization_confirmed"):
        raise HTTPException(status_code=403, detail="Authorization is not confirmed")
    if payload.transform not in {
        str(source).casefold()
        for source in metadata.get("permitted_sources", [])
    }:
        raise HTTPException(
            status_code=403,
            detail="Transform is outside the approved source scope",
        )
    try:
        expiry = datetime.fromisoformat(
            str(metadata.get("authorization_expires_at")).replace("Z", "+00:00")
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=403,
            detail="Authorization expiry is invalid",
        ) from exc
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Authorization has expired")
    max_depth = max(0, int(os.getenv("MAX_PIVOT_DEPTH", "2")))
    if payload.pivot_depth > max_depth:
        raise HTTPException(status_code=400, detail="Pivot depth limit exceeded")
    spec = _TRANSFORM_CATALOG[payload.transform]
    if spec["authenticated"] and not metadata.get("allow_authenticated_transforms"):
        raise HTTPException(
            status_code=403,
            detail="Authenticated transforms were not approved for this case",
        )


def _append_transform_run(
    metadata: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    runs = [
        dict(item)
        for item in metadata.get("transform_runs", [])
        if isinstance(item, dict)
    ][-99:]
    runs.append(run)
    return {**metadata, "transform_runs": runs}


def _active_transform_run_count(metadata: dict[str, Any]) -> int:
    return sum(
        1
        for item in metadata.get("transform_runs", [])
        if isinstance(item, dict)
        and item.get("status") in {"queued", "running"}
    )


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
@app.get("/healthz", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/investigations")
async def list_investigations(
    limit: int = Query(default=25, ge=1, le=100),
) -> list[dict[str, Any]]:
    async with sessions() as session:
        investigations = (
            await session.scalars(
                select(Investigation)
                .order_by(Investigation.created_at.desc())
                .limit(limit)
            )
        ).all()
        return [
            await _serialize(session, investigation) for investigation in investigations
        ]


@app.post("/api/investigations", status_code=202)
async def create_investigation(payload: InvestigationCreate) -> dict[str, Any]:
    metadata = {
        "authorization_confirmed": True,
        "authorization_reference": payload.authorization_reference,
        "authorization_expires_at": payload.authorization_expires_at.isoformat(),
        "lawful_purpose": payload.lawful_purpose,
        "permitted_sources": payload.permitted_sources,
        "employer": payload.employer,
        "location": payload.location,
        "authorized_domains": payload.authorized_domains,
        "authorized_ips": payload.authorized_ips,
        "additional_usernames": payload.additional_usernames,
        "allow_infrastructure_enrichment": payload.allow_infrastructure_enrichment,
        "allow_authenticated_transforms": payload.allow_authenticated_transforms,
        "compare_previous_cases": payload.compare_previous_cases,
    }
    investigation = Investigation(
        target_name=payload.target_name.strip(),
        target_aliases=[
            alias.strip() for alias in payload.target_aliases if alias.strip()
        ],
        target_username=payload.target_username,
        target_email=payload.target_email,
        status=InvestigationStatus.PENDING,
        depth=payload.depth,
        case_metadata=metadata,
    )

    async with sessions() as session:
        session.add(investigation)
        await session.commit()
        await session.refresh(investigation)

        try:
            celery.send_task(
                "deepvault.run_investigation",
                args=[str(investigation.id)],
            )
        except Exception as exc:
            failed_metadata = dict(metadata)
            failed_metadata["error"] = (
                f"{type(exc).__name__}: unable to queue worker task"
            )
            investigation.status = InvestigationStatus.FAILED
            investigation.case_metadata = failed_metadata
            await session.commit()
            raise HTTPException(
                status_code=503,
                detail="Investigation saved, but the worker could not be reached",
            ) from exc

        return await _serialize(session, investigation)


@app.get("/api/investigations/{investigation_id}")
async def get_investigation(investigation_id: UUID) -> dict[str, Any]:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        return await _serialize(session, investigation, include_report=True)


@app.get("/api/transforms")
async def list_transforms() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "transforms": [
            {"name": name, **spec}
            for name, spec in sorted(_TRANSFORM_CATALOG.items())
        ],
    }


@app.get("/api/investigations/{investigation_id}/graph")
async def get_graph(investigation_id: UUID) -> dict[str, Any]:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        return _graph_document(investigation)


@app.get("/api/investigations/{investigation_id}/graph.json")
async def download_graph_json(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        document = _redact_for_display(_graph_document(investigation))
        filename = f"deepvault-{investigation_id}-graph.json"
        return Response(
            json.dumps(document, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/api/investigations/{investigation_id}/graph.graphml")
async def download_graphml(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        filename = f"deepvault-{investigation_id}.graphml"
        return Response(
            _graphml_document(investigation),
            media_type="application/graphml+xml",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/api/investigations/{investigation_id}/graph.gexf")
async def download_gexf(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        filename = f"deepvault-{investigation_id}.gexf"
        return Response(
            _gexf_document(investigation),
            media_type="application/gexf+xml",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/api/investigations/{investigation_id}/graph.csv")
async def download_graph_csv(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        filename = f"deepvault-{investigation_id}-graph.csv"
        return Response(
            _graph_csv_document(investigation),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/api/investigations/{investigation_id}/mapping.osint.json")
async def download_mapping_project(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        document = _redact_for_display(_mapping_document(investigation))
        filename = f"deepvault-{investigation_id}.osint.json"
        return Response(
            json.dumps(document, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.post("/api/investigations/{investigation_id}/graph-layout")
async def update_graph_layout(
    investigation_id: UUID,
    payload: GraphLayoutUpdate,
) -> dict[str, Any]:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        graph = _stored_graph(investigation)
        valid_node_ids = {
            str(node.get("id"))
            for node in graph.get("nodes", [])
            if isinstance(node, dict) and node.get("id")
        }
        supplied_ids = {node.id for node in payload.nodes}
        if supplied_ids - valid_node_ids:
            raise HTTPException(
                status_code=400,
                detail="Layout contains nodes outside this case graph",
            )
        metadata = investigation.case_metadata or {}
        investigation.case_metadata = {
            **metadata,
            "graph_layout": {
                "nodes": [node.model_dump() for node in payload.nodes],
                "viewport": payload.viewport,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        await session.commit()
        return {
            "caseId": str(investigation.id),
            "nodeCount": len(payload.nodes),
            "status": "saved",
        }


@app.post("/api/investigations/{investigation_id}/transforms", status_code=202)
async def execute_transform(
    investigation_id: UUID,
    payload: TransformRequest,
) -> dict[str, Any]:
    async with sessions() as session:
        investigation = (
            await session.execute(
                select(Investigation)
                .where(Investigation.id == investigation_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        _require_transform_authorization(investigation, payload)
        run_id = f"TRUN-{uuid4().hex[:12].upper()}"
        metadata = investigation.case_metadata or {}
        max_parallel = max(1, int(os.getenv("MAX_PARALLEL_TRANSFORMS", "6")))
        if _active_transform_run_count(metadata) >= max_parallel:
            raise HTTPException(
                status_code=429,
                detail="The case has reached its parallel transform limit",
            )
        investigation.case_metadata = _append_transform_run(
            metadata,
            {
                "id": run_id,
                "transform": payload.transform,
                "entity_type": payload.entity_type,
                "evidence_ids": payload.evidence_ids,
                "pivot_depth": payload.pivot_depth,
                "status": "queued",
                "queued_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        await session.commit()
        try:
            celery.send_task(
                "deepvault.run_transform",
                args=[
                    str(investigation.id),
                    payload.transform,
                    {
                        "type": payload.entity_type,
                        "value": payload.value,
                        "evidence_ids": payload.evidence_ids,
                    },
                    payload.pivot_depth,
                    run_id,
                ],
            )
        except Exception as exc:
            metadata = investigation.case_metadata or {}
            runs = [
                {
                    **item,
                    **(
                        {
                            "status": "failed",
                            "error": "Worker queue is unavailable",
                        }
                        if isinstance(item, dict) and item.get("id") == run_id
                        else {}
                    ),
                }
                for item in metadata.get("transform_runs", [])
            ]
            investigation.case_metadata = {**metadata, "transform_runs": runs}
            await session.commit()
            raise HTTPException(
                status_code=503,
                detail="Transform was not queued because the worker is unavailable",
            ) from exc
        return {
            "caseId": str(investigation.id),
            "runId": run_id,
            "transform": payload.transform,
            "status": "queued",
        }


@app.get("/api/investigations/{investigation_id}/events")
async def stream_case_events(investigation_id: UUID) -> StreamingResponse:
    async with sessions() as session:
        await _get_investigation(session, investigation_id)

    async def event_stream():
        previous = ""
        for _ in range(900):
            async with sessions() as session:
                investigation = await _get_investigation(session, investigation_id)
                payload = await _serialize(
                    session,
                    investigation,
                    include_report=True,
                )
            serialized = json.dumps(
                _redact_for_display(payload),
                default=str,
                sort_keys=True,
            )
            if serialized != previous:
                yield f"event: case\ndata: {serialized}\n\n"
                previous = serialized
            else:
                yield "event: heartbeat\ndata: {}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/investigations/{investigation_id}/report.json")
async def download_json_report(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        report = (investigation.case_metadata or {}).get("structured_report")
        if not isinstance(report, dict):
            raise HTTPException(status_code=409, detail="Report is not ready")
        report = _redact_for_display(report)
        metadata = investigation.case_metadata or {}
        document = {
            **report,
            "case_context": {
                "case_id": str(investigation.id),
                "target_name": investigation.target_name,
                "target_username": investigation.target_username,
                "additional_usernames": metadata.get("additional_usernames", []),
                "target_email": investigation.target_email,
                "authorization_reference": metadata.get("authorization_reference"),
                "permitted_sources": metadata.get("permitted_sources", []),
            },
        }
        filename = f"deepvault-{investigation_id}.json"
        return Response(
            json.dumps(document, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


def render_report_html(
    report: dict[str, Any],
    target_name: str,
    review_summary: dict[str, Any] | None = None,
) -> str:
    report = _redact_for_display(report)
    review_summary = _redact_for_display(review_summary or {})

    def safe(value: Any) -> str:
        return escape(str(value if value is not None else ""))

    def confidence_label(value: Any) -> str:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return str(value if value is not None else "")
        if 0.0 <= score <= 1.0:
            return f"{score * 100:.0f}%"
        return str(value)

    def evidence_citations(values: Any, limit: int = 8) -> str:
        evidence_ids = [
            str(value)
            for value in (values if isinstance(values, list) else [])
            if value
        ]
        visible = evidence_ids[:limit]
        remaining = len(evidence_ids) - len(visible)
        citation_text = ", ".join(visible)
        if remaining:
            citation_text += f" · +{remaining} more in the evidence appendix"
        return (
            f"<span class='citations'>{safe(citation_text)}</span>"
            if citation_text
            else "<span class='citations'>No evidence ID</span>"
        )

    def public_link(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        try:
            parsed = urlsplit(value)
        except ValueError:
            return ""
        if parsed.scheme not in {"http", "https"}:
            return ""
        return (
            f"<a class='review-link' href='{safe(value)}' "
            "target='_blank' rel='noreferrer'>Open public page</a>"
        )

    verdict = review_summary.get("verdict", {})
    verdict = verdict if isinstance(verdict, dict) else {}
    review_counts = review_summary.get("counts", {})
    review_counts = review_counts if isinstance(review_counts, dict) else {}
    review_leads = review_summary.get("priority_leads", [])
    review_leads = review_leads if isinstance(review_leads, list) else []
    review_key_points = review_summary.get("key_points", [])
    review_key_points = (
        review_key_points if isinstance(review_key_points, list) else []
    )
    review_cautions = review_summary.get("cautions", [])
    review_cautions = (
        review_cautions if isinstance(review_cautions, list) else []
    )

    review_lead_cards = "".join(
        (
            "<article class='review-lead'>"
            f"<div class='rank'>{safe(index)}</div>"
            "<div>"
            f"<h3>{safe(item.get('label') or item.get('entity_id'))}</h3>"
            f"<span class='review-badge'>{safe(item.get('confidence_label'))}</span>"
            f"<p>{safe(item.get('explanation'))}</p>"
            f"<p class='meta'>Sources: "
            f"{safe(' + '.join(item.get('source_tools', [])) or 'unknown')} · "
            f"Technical confidence: "
            f"{safe(confidence_label(item.get('technical_confidence')))}</p>"
            f"{evidence_citations(item.get('evidence_ids'))}"
            f"{public_link(item.get('public_url'))}"
            "</div>"
            "</article>"
        )
        for index, item in enumerate(review_leads[:10], start=1)
        if isinstance(item, dict)
    )
    review_points = "".join(
        (
            "<article class='plain-point'>"
            f"<h3>{safe(item.get('title'))}</h3>"
            f"<p>{safe(item.get('statement'))}</p>"
            f"{evidence_citations(item.get('evidence_ids'))}"
            "</article>"
        )
        for item in review_key_points
        if isinstance(item, dict)
    )
    caution_items = "".join(
        (
            "<li>"
            f"{safe(item.get('statement'))}"
            f"{evidence_citations(item.get('evidence_ids'))}"
            "</li>"
        )
        for item in review_cautions
        if isinstance(item, dict) and item.get("evidence_ids")
    )
    review_overview = ""
    if verdict:
        review_overview = (
            "<section class='plain-review'>"
            "<p class='eyebrow'>PLAIN-LANGUAGE ASSESSMENT</p>"
            f"<h2>{safe(verdict.get('title'))}</h2>"
            f"<p class='verdict-copy'>{safe(verdict.get('explanation'))}</p>"
            f"{evidence_citations(verdict.get('evidence_ids'))}"
            "<div class='review-counts'>"
            f"<div><strong>{safe(review_counts.get('supported', 0))}</strong>"
            "<span>Supported</span></div>"
            f"<div><strong>{safe(review_counts.get('review_first', 0))}</strong>"
            "<span>Check first</span></div>"
            f"<div><strong>{safe(review_counts.get('low_signal', 0))}</strong>"
            "<span>Unverified</span></div>"
            f"<div><strong>{safe(review_counts.get('suppressed', 0))}</strong>"
            "<span>Hidden noise</span></div>"
            "</div>"
            "<div class='how-to-read'><strong>How to read this report</strong>"
            "<p>A candidate means a public trace is worth checking. It does not "
            "mean DeepVault verified that the person owns the account.</p></div>"
            "<h2>What to check first</h2>"
            f"{review_lead_cards or '<p>No prioritized review lead was produced.</p>'}"
            "<div class='plain-grid'>"
            f"<section><h2>What was actually found</h2>{review_points}</section>"
            "<section><h2>What you must not conclude</h2>"
            f"<ul class='cautions'>{caution_items}</ul>"
            + (
                "<div class='privacy-note'>"
                f"{safe(review_counts.get('suppressed', 0))} misleading, generic, "
                "rejected, or sensitive candidate(s) are hidden from this review "
                "queue and retained only in the authorized evidence appendix."
                "</div>"
                if review_counts.get("suppressed")
                else ""
            )
            + "</section></div>"
            "</section>"
        )

    finding_groups: dict[str, list[str]] = {}
    for item in report.get("findings", []):
        finding_limitations = "".join(
            f"<li>{safe(limitation)}</li>"
            for limitation in item.get("limitations", [])
        )
        category = str(item.get("category") or "other_observations")
        finding_groups.setdefault(category, []).append(
            "<article class='finding'>"
            f"<h3>{safe(item.get('title'))}</h3>"
            f"<p>{safe(item.get('statement'))}</p>"
            f"<p class='meta'>Status "
            f"{safe(item.get('verification_status') or 'unverified')} · "
            f"Confidence {safe(confidence_label(item.get('confidence')))} · "
            f"Evidence {safe(', '.join(item.get('evidence_ids', [])))}</p>"
            f"{f'<ul>{finding_limitations}</ul>' if finding_limitations else ''}"
            "</article>"
        )
    finding_labels = {
        "corroborated_facts": "Corroborated facts",
        "probable_profiles": "Probable profiles",
        "possible_profiles": "Possible profiles",
        "defensive_exposure": "Defensive exposure",
        "service_signals": "Service-presence signals",
        "unverified_profiles": "Unverified username leads",
        "quarantined_candidates": "Quarantined sensitive candidates",
        "rejected_observations": "Rejected observations",
        "other_observations": "Other observations",
    }
    findings = "".join(
        f"<h3>{safe(finding_labels.get(category, category))}</h3>"
        + "".join(finding_groups.get(category, []))
        for category in finding_labels
        if finding_groups.get(category)
    )
    coverage = "".join(
        (
            "<tr>"
            f"<td>{safe(item.get('source'))}</td>"
            f"<td>{safe(item.get('evidence_count'))}</td>"
            f"<td>{safe(str(item.get('status') or '').replace('_', ' '))}</td>"
            f"<td>{safe(item.get('detail'))}</td>"
            f"<td>{safe(', '.join(item.get('evidence_ids', [])))}</td>"
            "</tr>"
        )
        for item in report.get("source_coverage", [])
    )
    timeline = "".join(
        (
            "<article class='finding'>"
            f"<p class='meta'>{safe(item.get('occurred_at'))}</p>"
            f"<p>{safe(item.get('description'))}</p>"
            f"<p class='meta'>Evidence "
            f"{safe(', '.join(item.get('evidence_ids', [])))}</p>"
            "</article>"
        )
        for item in report.get("timeline", [])
    )
    contradictions = "".join(
        (
            "<article class='finding'>"
            f"<p>{safe(item.get('description'))}</p>"
            f"<p>{safe(item.get('recommendation'))}</p>"
            f"<p class='meta'>Evidence "
            f"{safe(', '.join(item.get('evidence_ids', [])))}</p>"
            "</article>"
        )
        for item in report.get("contradictions", [])
    )
    identity_graph = report.get("identity_graph")
    identity_graph = identity_graph if isinstance(identity_graph, dict) else {}
    graph_nodes = identity_graph.get("nodes", [])
    graph_nodes = graph_nodes if isinstance(graph_nodes, list) else []
    graph_edge_items = identity_graph.get("edges", [])
    graph_edge_items = graph_edge_items if isinstance(graph_edge_items, list) else []
    graph_hypothesis_items = identity_graph.get("hypotheses", [])
    graph_hypothesis_items = (
        graph_hypothesis_items if isinstance(graph_hypothesis_items, list) else []
    )
    graph_pivot_items = identity_graph.get("pivots", [])
    graph_pivot_items = (
        graph_pivot_items if isinstance(graph_pivot_items, list) else []
    )
    node_labels = {
        str(item.get("id")): item.get("label") or item.get("id")
        for item in graph_nodes
        if isinstance(item, dict) and item.get("id")
    }
    node_by_id = {
        str(item.get("id")): item
        for item in graph_nodes
        if isinstance(item, dict) and item.get("id")
    }
    reviewable_statuses = {"confirmed", "highly_probable", "probable", "possible"}

    def graph_item_is_reviewable(item: dict[str, Any], node_key: str) -> bool:
        node = node_by_id.get(str(item.get(node_key)), {})
        attributes = node.get("attributes")
        attributes = attributes if isinstance(attributes, dict) else {}
        status = attributes.get("verification_status") or item.get("identity_status")
        return str(status or "").casefold() in reviewable_statuses

    primary_graph_hypotheses = [
        item
        for item in graph_hypothesis_items
        if isinstance(item, dict)
        and graph_item_is_reviewable(item, "object_node_id")
    ]
    secondary_graph_hypothesis_count = (
        len(graph_hypothesis_items) - len(primary_graph_hypotheses)
    )
    graph_hypotheses = "".join(
        (
            "<article class='finding'>"
            f"<h3>{safe(item.get('identity_status'))} · "
            f"{safe(confidence_label(item.get('confidence')))}</h3>"
            f"<p>{safe(item.get('claim'))}</p>"
            f"<p class='meta'>Evidence "
            f"{safe(', '.join(item.get('evidence_ids', [])))}</p>"
            + (
                "<ul>"
                + "".join(
                    f"<li>{safe(limitation)}</li>"
                    for limitation in item.get("limitations", [])
                )
                + "</ul>"
                if item.get("limitations")
                else ""
            )
            + "</article>"
        )
        for item in primary_graph_hypotheses
    )
    graph_edges = "".join(
        (
            "<tr>"
            f"<td>{safe(_PLAIN_RELATIONSHIP_LABELS.get(str(item.get('relationship')), str(item.get('relationship') or '').replace('_', ' ').capitalize()))}</td>"
            f"<td>{safe(node_labels.get(str(item.get('source_node_id')), item.get('source_node_id')))}</td>"
            f"<td>{safe(node_labels.get(str(item.get('target_node_id')), item.get('target_node_id')))}</td>"
            f"<td>{safe(confidence_label(item.get('confidence')))}</td>"
            f"<td>{safe(item.get('identity_status'))}</td>"
            f"<td>{safe(', '.join(item.get('evidence_ids', [])))}</td>"
            "</tr>"
        )
        for item in graph_edge_items
        if isinstance(item, dict)
    )
    primary_graph_pivots = [
        item
        for item in graph_pivot_items
        if isinstance(item, dict) and graph_item_is_reviewable(item, "node_id")
    ]
    graph_pivots = "".join(
        (
            "<article class='finding'>"
            f"<h3>#{safe(item.get('rank'))} · {safe(item.get('title'))}</h3>"
            f"<p>{safe(item.get('rationale'))}</p>"
            f"<p>{safe(item.get('action'))}</p>"
            "<p class='meta'>Manual review only · new authorization required · "
            f"{safe(item.get('priority'))} priority</p>"
            f"<p class='meta'>Evidence "
            f"{safe(', '.join(item.get('evidence_ids', [])))}</p>"
            "</article>"
        )
        for item in primary_graph_pivots
    )
    temporal = report.get("temporal_comparison")
    temporal = temporal if isinstance(temporal, dict) else {}
    temporal_counts = temporal.get("counts")
    temporal_counts = temporal_counts if isinstance(temporal_counts, dict) else {}
    temporal_groups = []
    for key, label in (
        ("added", "Added"),
        ("changed", "Changed"),
        ("persisting", "Persisting"),
        ("not_observed", "Not observed"),
    ):
        entries = temporal.get(key, [])
        if not isinstance(entries, list) or not entries:
            continue
        parts = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            evidence_ids = [
                value
                for value in (
                    item.get("previous_evidence_id"),
                    item.get("current_evidence_id"),
                )
                if value
            ]
            changed_fields = item.get("changed_fields", [])
            parts.append(
                "<article class='finding'>"
                f"<h3>{safe(item.get('type'))} · {safe(item.get('value'))}</h3>"
                + (
                    f"<p class='meta'>Changed fields: "
                    f"{safe(', '.join(changed_fields))}</p>"
                    if changed_fields
                    else ""
                )
                + f"<p class='meta'>Evidence {safe(' → '.join(evidence_ids))}</p>"
                "</article>"
            )
        if parts:
            temporal_groups.append(f"<h3>{safe(label)}</h3>{''.join(parts)}")
    temporal_scope = temporal.get("scope")
    temporal_scope = temporal_scope if isinstance(temporal_scope, dict) else {}
    temporal_section = ""
    if temporal:
        temporal_section = (
            "<h2>Changes since the previous comparable case</h2>"
            f"<p><strong>Baseline case:</strong> "
            f"{safe(temporal_scope.get('previous_case_id'))}</p>"
            "<p>"
            f"<strong>Added:</strong> {safe(temporal_counts.get('added', 0))} · "
            f"<strong>Changed:</strong> {safe(temporal_counts.get('changed', 0))} · "
            f"<strong>Persisting:</strong> {safe(temporal_counts.get('persisting', 0))} · "
            f"<strong>Not observed:</strong> "
            f"{safe(temporal_counts.get('not_observed', 0))}"
            "</p>"
            f"<div class='notice'>{safe(temporal.get('scope_note'))}</div>"
            + "".join(temporal_groups)
        )
    evidence_ledger = "".join(
        (
            "<article class='finding'>"
            f"<h3>{safe(item.get('id'))} · {safe(item.get('source'))}</h3>"
            f"<p><strong>Type:</strong> {safe(item.get('type'))} · "
            f"<strong>Confidence:</strong> "
            f"{safe(confidence_label(item.get('confidence')))} · "
            f"<strong>Identity:</strong> {safe(item.get('identity_status'))}</p>"
            f"<p><strong>Value:</strong> {safe(item.get('value'))}</p>"
            f"<p><strong>Source URL:</strong> {safe(item.get('source_url'))}</p>"
            f"<p class='meta'>Observed {safe(item.get('observed_at'))}</p>"
            f"<pre>{safe(json.dumps(item.get('metadata', {}), indent=2, default=str))}</pre>"
            "</article>"
        )
        for item in report.get("evidence_ledger", [])
    )
    recommendations = "".join(
        f"<li>{safe(item)}</li>" for item in report.get("recommendations", [])
    )
    limitations = "".join(
        f"<li>{safe(item)}</li>" for item in report.get("limitations", [])
    )
    methodology = "".join(
        f"<li>{safe(item)}</li>" for item in report.get("methodology", [])
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DeepVault report — {safe(target_name)}</title>
	  <style>
	    body {{ font: 15px/1.55 Inter, system-ui, sans-serif; color: #18221d;
	      max-width: 900px; margin: 0 auto; padding: 48px; }}
	    header {{ border-bottom: 3px solid #1d7a4d; margin-bottom: 32px; }}
	    h1 {{ margin-bottom: 4px; }} h2 {{ margin-top: 32px; }}
	    .plain-review {{ border: 2px solid #284e7a; border-radius: 14px;
	      padding: 24px; margin: 22px 0 32px; background: #f4f8fc; }}
	    .plain-review > h2:first-of-type {{ margin-top: 4px; font-size: 28px; }}
	    .eyebrow {{ color: #284e7a; font-size: 12px; font-weight: 800;
	      letter-spacing: .08em; }}
	    .verdict-copy {{ font-size: 17px; }}
	    .review-counts {{ display: grid; grid-template-columns: repeat(4, 1fr);
	      gap: 8px; margin: 20px 0; }}
	    .review-counts div {{ border: 1px solid #ccd9e6; border-radius: 8px;
	      padding: 12px; background: white; }}
	    .review-counts strong, .review-counts span {{ display: block; }}
	    .review-counts strong {{ font-size: 24px; }}
	    .review-counts span {{ color: #52635a; font-size: 11px;
	      text-transform: uppercase; }}
	    .how-to-read {{ border-left: 4px solid #d09a00; padding: 10px 14px;
	      margin: 18px 0; background: #fff7db; }}
	    .how-to-read p {{ margin: 4px 0 0; }}
	    .review-lead {{ display: grid; grid-template-columns: 34px 1fr; gap: 12px;
	      border: 1px solid #d7e3da; border-left: 4px solid #d09a00;
	      border-radius: 9px; padding: 14px; margin: 9px 0; background: white; }}
	    .review-lead h3, .plain-point h3 {{ margin: 0 0 5px; }}
	    .rank {{ display: grid; place-items: center; width: 30px; height: 30px;
	      border-radius: 50%; background: #284e7a; color: white; font-weight: 800; }}
	    .review-badge {{ display: inline-block; border-radius: 999px;
	      padding: 3px 8px; background: #fff0bb; color: #795900;
	      font-size: 11px; font-weight: 800; text-transform: uppercase; }}
	    .citations {{ display: block; color: #8a2631; font: 11px ui-monospace,
	      SFMono-Regular, monospace; margin-top: 7px; overflow-wrap: anywhere; }}
	    .review-link {{ display: inline-block; margin-top: 8px; color: #1e5c98; }}
	    .plain-grid {{ display: grid; grid-template-columns: 1fr 1fr;
	      gap: 18px; margin-top: 22px; }}
	    .plain-point {{ border-top: 1px solid #d7e3da; padding: 12px 0; }}
	    .cautions {{ padding-left: 20px; }}
	    .cautions li {{ margin: 0 0 14px; }}
	    .privacy-note {{ background: #fae9ec; border: 1px solid #dfb3ba;
	      border-radius: 8px; padding: 12px; color: #742c37; }}
	    .summary, .finding {{ background: #f3f7f4; border: 1px solid #d7e3da;
	      border-radius: 10px; padding: 18px; margin: 12px 0; }}
    .notice {{ background: #fff7db; border: 1px solid #ead58a;
      border-radius: 10px; padding: 14px; margin: 12px 0; }}
    .meta {{ color: #52635a; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #d7e3da; padding: 10px; text-align: left; }}
	    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #e8f0ea;
	      border-radius: 8px; padding: 12px; font-size: 12px; }}
	    details.technical {{ margin: 14px 0; }}
	    details.technical summary {{ cursor: pointer; color: #284e7a;
	      font-weight: 800; }}
	    @media (max-width: 680px) {{
	      body {{ padding: 22px; }}
	      .review-counts, .plain-grid {{ grid-template-columns: 1fr 1fr; }}
	    }}
	    @media print {{
	      body {{ padding: 0; }}
	      details.technical {{ display: block; }}
	      details.technical > * {{ display: block; }}
	    }}
  </style>
</head>
<body>
	  <header>
    <p>DEEPVAULT · AUTHORIZED PERSON INTELLIGENCE</p>
    <h1>{safe(target_name)}</h1>
    <p class="meta">Report {safe(report.get("report_id"))} ·
	      {safe(report.get("generated_at"))}</p>
	  </header>
	  {review_overview}
	  <section class="summary">
    <h2>Executive summary</h2>
    <p>{safe(report.get("executive_summary"))}</p>
    <p><strong>Identity confidence:</strong>
      {safe(report.get("identity_confidence"))} ·
      <strong>Risk:</strong> {safe(report.get("overall_risk"))} ·
      <strong>Coverage:</strong> {safe(report.get("coverage_assessment"))} ·
      <strong>Evidence:</strong> {safe(report.get("evidence_count"))}</p>
    <p class="meta">Evidence citations:
      {safe(", ".join(report.get("executive_summary_evidence_ids", [])))}</p>
  </section>
  <h2>Findings</h2>
  {findings or "<p>No evidence-backed findings were produced.</p>"}
  <h2>Evidence-first identity analysis</h2>
  <p><strong>Graph:</strong> {safe(len(graph_nodes))} nodes ·
    {safe(len(graph_edge_items))} relationships ·
    {safe(len(primary_graph_hypotheses))} reviewable hypotheses ·
    {safe(secondary_graph_hypothesis_count)} low-signal hypotheses retained in JSON</p>
	  {graph_hypotheses or "<p>No evidence-backed identity hypotheses were produced.</p>"}
	  <details class="technical">
	    <summary>Full technical provenance · {safe(len(graph_edge_items))} relationships</summary>
	    <p class="meta">These rows document which tool published each observation.
	      They are not additional identity matches.</p>
	    <table><thead><tr><th>Relation</th><th>From</th><th>To</th>
	      <th>Confidence</th><th>Status</th><th>Evidence IDs</th></tr></thead>
	      <tbody>{graph_edges}</tbody></table>
	  </details>
  <h3>Ranked analyst pivots</h3>
  {graph_pivots or "<p>No evidence-backed pivots were produced.</p>"}
  {temporal_section}
  <h2>Source coverage</h2>
  <table><thead><tr><th>Source</th><th>Evidence</th><th>Status</th>
    <th>Coverage note</th><th>Evidence IDs</th></tr></thead>
    <tbody>{coverage}</tbody></table>
  <h2>Evidence-derived timeline</h2>
  {timeline or "<p>No source-provided event dates were available. Collection timestamps are intentionally excluded because they are not person-history events.</p>"}
  <h2>Contradictions</h2>
  {contradictions or "<p>No contradiction entries were produced.</p>"}
  <h2>Evidence appendix</h2>
  {evidence_ledger or "<p>No evidence records were produced.</p>"}
  <h2>Recommendations</h2>
  <ul>{recommendations}</ul>
  <h2>Limitations</h2>
  <ul>{limitations}</ul>
  <h2>Methodology</h2>
  <ul>{methodology}</ul>
</body>
</html>"""


@app.get("/api/investigations/{investigation_id}/report.html")
async def download_html_report(investigation_id: UUID) -> Response:
    async with sessions() as session:
        investigation = await _get_investigation(session, investigation_id)
        report = (investigation.case_metadata or {}).get("structured_report")
        if not isinstance(report, dict):
            raise HTTPException(status_code=409, detail="Report is not ready")
        report = _redact_for_display(report)
        review_summary = _graph_document(investigation).get("review_summary", {})
        filename = f"deepvault-{investigation_id}.html"
        return Response(
            render_report_html(
                report,
                investigation.target_name,
                review_summary=review_summary,
            ),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
