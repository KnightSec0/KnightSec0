"""Local FastAPI dashboard for authorized DeepVault investigations."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from html import escape
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote_plus
from uuid import UUID, uuid4

from celery import Celery
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
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
    target_email: str | None = Field(default=None, max_length=320)
    employer: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    authorized_domains: list[str] = Field(default_factory=list, max_length=20)
    authorized_ips: list[str] = Field(default_factory=list, max_length=20)
    allow_infrastructure_enrichment: bool = False
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
        if not self.target_username and not self.target_email:
            raise ValueError("Provide at least one username or email")
        infrastructure_sources = {"shodan", "censys"} & set(self.permitted_sources)
        if infrastructure_sources and (
            not self.allow_infrastructure_enrichment or not self.authorized_ips
        ):
            raise ValueError(
                "Shodan and Censys require infrastructure consent and an authorized IP"
            )
        return self


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
        "target_email": investigation.target_email,
        "status": _status_value(investigation.status),
        "depth": investigation.depth,
        "risk_score": investigation.risk_score,
        "created_at": investigation.created_at,
        "updated_at": investigation.updated_at,
        "completed_at": investigation.completed_at,
        "authorization_reference": metadata.get("authorization_reference"),
        "permitted_sources": metadata.get("permitted_sources", []),
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
        "allow_infrastructure_enrichment": payload.allow_infrastructure_enrichment,
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


def render_report_html(report: dict[str, Any], target_name: str) -> str:
    report = _redact_for_display(report)

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

    finding_parts = []
    for item in report.get("findings", []):
        finding_limitations = "".join(
            f"<li>{safe(limitation)}</li>"
            for limitation in item.get("limitations", [])
        )
        finding_parts.append(
            "<article class='finding'>"
            f"<h3>{safe(item.get('title'))}</h3>"
            f"<p>{safe(item.get('statement'))}</p>"
            f"<p class='meta'>Confidence "
            f"{safe(confidence_label(item.get('confidence')))} · "
            f"Evidence {safe(', '.join(item.get('evidence_ids', [])))}</p>"
            f"{f'<ul>{finding_limitations}</ul>' if finding_limitations else ''}"
            "</article>"
        )
    findings = "".join(finding_parts)
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
    .summary, .finding {{ background: #f3f7f4; border: 1px solid #d7e3da;
      border-radius: 10px; padding: 18px; margin: 12px 0; }}
    .meta {{ color: #52635a; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #d7e3da; padding: 10px; text-align: left; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #e8f0ea;
      border-radius: 8px; padding: 12px; font-size: 12px; }}
    @media print {{ body {{ padding: 0; }} }}
  </style>
</head>
<body>
  <header>
    <p>DEEPVAULT · AUTHORIZED PERSON INTELLIGENCE</p>
    <h1>{safe(target_name)}</h1>
    <p class="meta">Report {safe(report.get("report_id"))} ·
      {safe(report.get("generated_at"))}</p>
  </header>
  <section class="summary">
    <h2>Executive summary</h2>
    <p>{safe(report.get("executive_summary"))}</p>
    <p><strong>Identity confidence:</strong>
      {safe(report.get("identity_confidence"))} ·
      <strong>Risk:</strong> {safe(report.get("overall_risk"))} ·
      <strong>Evidence:</strong> {safe(report.get("evidence_count"))}</p>
    <p class="meta">Evidence citations:
      {safe(", ".join(report.get("executive_summary_evidence_ids", [])))}</p>
  </section>
  <h2>Findings</h2>
  {findings or "<p>No evidence-backed findings were produced.</p>"}
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
        filename = f"deepvault-{investigation_id}.html"
        return Response(
            render_report_html(report, investigation.target_name),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
