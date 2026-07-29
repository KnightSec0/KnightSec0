"""
WorldAtlas Orchestrator — Celery entrypoint and task definitions.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from celery import Celery
from celery.signals import worker_ready, worker_shutdown
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import noload, sessionmaker
from sqlalchemy.pool import NullPool

from config import settings
from db.models import Base, Investigation, InvestigationStatus, Artifact
from investigators.identity import IdentityInvestigator
from investigators.social import SocialMediaInvestigator
from investigators.breach import BreachInvestigator
from investigators.darkweb import DarkWebInvestigator
from investigators.documents import DocumentInvestigator
from investigators.geolocation import GeolocationInvestigator
from investigators.financial import FinancialInvestigator
from investigators.email_footprint import EmailFootprintInvestigator
from investigators.person_intelligence import PersonIntelligenceInvestigator
from intelligence.models import Evidence, InvestigationTarget
from intelligence.policy import CollectionPolicy
from intelligence.redaction import redact_sensitive
from reporting.person_report import PersonReportGenerator
from transforms import (
    TransformBudgets,
    TransformContext,
    TransformEntity,
    TransformRunner,
    build_default_registry,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("deepvault.orchestrator")

# ---------------------------------------------------------------------------
# Celery app
# ---------------------------------------------------------------------------
app = Celery(
    "deepvault",
    broker=settings.celery_broker,
    backend=settings.celery_broker,
)
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "periodic-healthcheck": {
            "task": "deepvault.periodic_healthcheck",
            "schedule": 300.0,  # every 5 minutes
        },
    },
)

# ---------------------------------------------------------------------------
# Database engine
# ---------------------------------------------------------------------------
# Celery invokes each synchronous task through ``asyncio.run()``, which creates a
# fresh event loop. Async driver connections cannot be reused across those loops,
# so retaining them in SQLAlchemy's default pool eventually raises
# "Future attached to a different loop" on a worker's second task.
engine = create_async_engine(settings.db_url, echo=False, poolclass=NullPool)
async_session_factory = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def create_tables():
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified/created.")


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
@app.task(
    bind=True,
    name="deepvault.run_investigation",
    max_retries=3,
    default_retry_delay=60,
)
def run_investigation(self, investigation_id: str):
    """Entry point: run full investigation pipeline for a given ID."""
    delivery_info = getattr(self.request, "delivery_info", {}) or {}
    asyncio.run(
        _run_investigation_pipeline(
            investigation_id,
            redelivered=bool(delivery_info.get("redelivered")),
        )
    )


@app.task(name="deepvault.run_transform")
def run_transform(
    investigation_id: str,
    transform_name: str,
    entity_payload: dict,
    pivot_depth: int = 0,
    run_id: str | None = None,
):
    """Run one analyst-confirmed transform against an authorized case."""
    asyncio.run(
        _run_transform(
            investigation_id=investigation_id,
            transform_name=transform_name,
            entity_payload=entity_payload,
            pivot_depth=pivot_depth,
            run_id=run_id or f"TRUN-{uuid4().hex[:12].upper()}",
        )
    )


def _transform_budgets() -> TransformBudgets:
    return TransformBudgets(
        max_parallel_transforms=settings.max_parallel_transforms,
        max_results_per_transform=settings.max_results_per_transform,
        max_graph_nodes=settings.max_graph_nodes,
        max_pivot_depth=settings.max_pivot_depth,
        transform_timeout=settings.transform_timeout,
        cache_ttl_seconds=settings.transform_cache_ttl_seconds,
    )


def _transform_context(
    inv: Investigation,
    *,
    pivot_depth: int,
) -> TransformContext:
    _validate_scoped_authorization(inv)
    metadata = inv.case_metadata or {}
    return TransformContext(
        case_id=str(inv.id),
        authorization_reference=str(metadata["authorization_reference"]).strip(),
        lawful_purpose=str(metadata.get("lawful_purpose") or "").strip(),
        authorization_expires_at=datetime.fromisoformat(
            str(metadata["authorization_expires_at"]).replace("Z", "+00:00")
        ),
        permitted_transforms={
            str(source).strip().casefold()
            for source in metadata.get("permitted_sources", [])
            if str(source).strip()
        },
        authorized_domains={
            str(value).strip().casefold().rstrip(".")
            for value in metadata.get("authorized_domains", [])
            if str(value).strip()
        },
        authorized_ips={
            str(value).strip()
            for value in metadata.get("authorized_ips", [])
            if str(value).strip()
        },
        pivot_depth=pivot_depth,
        allow_infrastructure_enrichment=bool(
            settings.allow_infrastructure_enrichment
            and metadata.get("allow_infrastructure_enrichment")
        ),
        allow_authenticated_transforms=bool(
            settings.allow_authenticated_transforms
            and metadata.get("allow_authenticated_transforms")
        ),
        allow_sensitive_pivots=bool(settings.allow_sensitive_pivots),
    )


def _validate_transform_entity(
    inv: Investigation,
    entity: TransformEntity,
) -> None:
    """Require graph evidence unless the value was supplied in case scope."""
    metadata = inv.case_metadata or {}
    report = metadata.get("structured_report")
    ledger = report.get("evidence_ledger", []) if isinstance(report, dict) else []
    valid_evidence_ids = {
        str(item.get("id"))
        for item in ledger
        if isinstance(item, dict) and item.get("id")
    }
    if entity.evidence_ids:
        unknown = set(entity.evidence_ids) - valid_evidence_ids
        if unknown:
            raise PermissionError("Transform cites evidence outside this case")
        return

    scoped_values = {
        str(value).strip().casefold()
        for value in (
            inv.target_username,
            *(metadata.get("additional_usernames", []) or []),
            inv.target_email,
            *(metadata.get("authorized_domains", []) or []),
            *(metadata.get("authorized_ips", []) or []),
        )
        if value and str(value).strip()
    }
    if entity.type == "file":
        # The adapter independently confines files to TRANSFORM_UPLOAD_ROOT.
        return
    if entity.value.strip().casefold().rstrip(".") not in {
        value.rstrip(".") for value in scoped_values
    }:
        raise PermissionError(
            "A derived transform input must cite evidence from this case"
        )


def _transform_run_update(
    metadata: dict,
    run_id: str,
    **patch,
) -> dict:
    runs = [
        dict(item)
        for item in metadata.get("transform_runs", [])
        if isinstance(item, dict)
    ][-99:]
    found = False
    for item in runs:
        if item.get("id") == run_id:
            item.update(patch)
            found = True
            break
    if not found:
        runs.append({"id": run_id, **patch})
    return {**metadata, "transform_runs": runs}


def _transform_run_is_active(metadata: dict, run_id: str) -> bool:
    for item in metadata.get("transform_runs", []):
        if not isinstance(item, dict) or item.get("id") != run_id:
            continue
        if item.get("status") == "completed":
            return True
        if item.get("status") != "running":
            return False
        try:
            started = datetime.fromisoformat(
                str(item.get("started_at")).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            return False
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - started < timedelta(
            seconds=max(settings.transform_timeout * 2, 60)
        )
    return False


async def _run_transform(
    *,
    investigation_id: str,
    transform_name: str,
    entity_payload: dict,
    pivot_depth: int,
    run_id: str,
) -> None:
    inv_uuid = UUID(investigation_id)
    entity = TransformEntity.model_validate(entity_payload)
    registry = build_default_registry()
    runner = TransformRunner(registry, _transform_budgets())

    async with async_session_factory() as session:
        inv = (
            await session.execute(
                select(Investigation)
                .where(Investigation.id == inv_uuid)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if inv is None:
            raise ValueError("Investigation not found")
        if inv.status != InvestigationStatus.COMPLETED:
            raise ValueError("Transforms require a completed investigation")
        if _transform_run_is_active(inv.case_metadata or {}, run_id):
            logger.info("Transform run %s is already active or completed", run_id)
            return
        context = _transform_context(inv, pivot_depth=pivot_depth)
        _validate_transform_entity(inv, entity)
        graph = ((inv.case_metadata or {}).get("structured_report") or {}).get(
            "identity_graph"
        )
        current_graph_nodes = (
            len(graph.get("nodes", [])) if isinstance(graph, dict) else 0
        )
        inv.case_metadata = _transform_run_update(
            inv.case_metadata or {},
            run_id,
            transform=transform_name,
            entity_type=entity.type,
            evidence_ids=entity.evidence_ids,
            pivot_depth=pivot_depth,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        await session.commit()

    try:
        result = await runner.run(
            transform_name=transform_name,
            entity=entity,
            context=context,
            current_graph_nodes=current_graph_nodes,
        )
    except Exception as exc:
        async with async_session_factory() as session:
            inv = (
                await session.execute(
                    select(Investigation)
                    .where(Investigation.id == inv_uuid)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if inv is not None:
                inv.case_metadata = _transform_run_update(
                    inv.case_metadata or {},
                    run_id,
                    status="failed",
                    error=f"{type(exc).__name__}: transform failed",
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
                await session.commit()
        raise

    async with async_session_factory() as session:
        inv = (
            await session.execute(
                select(Investigation)
                .where(Investigation.id == inv_uuid)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if inv is None:
            raise ValueError("Investigation not found after transform")
        for evidence in result.evidence:
            session.add(
                Artifact(
                    investigation_id=inv_uuid,
                    source=evidence.source,
                    source_type=evidence.type,
                    identifier_type=entity.type,
                    identifier_value=(
                        Path(entity.value).name
                        if entity.type == "file"
                        else entity.value[:500]
                    ),
                    context={
                        "evidence": redact_sensitive(
                            evidence.model_dump(mode="json")
                        )
                    },
                    confidence=_confidence_label(evidence.confidence),
                )
            )
        await session.commit()

        artifacts = (
            await session.scalars(
                select(Artifact).where(Artifact.investigation_id == inv_uuid)
            )
        ).all()
        metadata = inv.case_metadata or {}
        source_status = [
            dict(item)
            for item in metadata.get("source_status", [])
            if isinstance(item, dict)
            and str(item.get("source")) != transform_name
        ]
        source_status.append(
            {
                "source": transform_name,
                "status": (
                    "evidence_collected"
                    if result.evidence
                    else "unavailable"
                    if result.errors
                    else "no_results"
                ),
                "evidence_count": len(result.evidence),
                **(
                    {
                        "reason_code": _connector_status_reason(result.errors),
                        "detail": _connector_status_detail(
                            transform_name,
                            result.errors,
                        ),
                    }
                    if result.errors
                    else {}
                ),
            }
        )
        target = {
            "name": inv.target_name,
            "aliases": inv.target_aliases or [],
            "username": inv.target_username,
            "usernames": [
                value
                for value in (
                    inv.target_username,
                    *(metadata.get("additional_usernames", []) or []),
                )
                if value
            ],
            "email": inv.target_email,
            "employer": metadata.get("employer"),
            "location": metadata.get("location"),
            "_source_status": sorted(
                source_status,
                key=lambda item: str(item.get("source")),
            ),
        }
        report = await PersonReportGenerator().generate(
            target=target,
            artifacts=list(artifacts),
            current_case_id=str(inv.id),
        )
        inv.case_metadata = _transform_run_update(
            {
                **metadata,
                "source_status": target["_source_status"],
                "structured_report": report.model_dump(mode="json"),
            },
            run_id,
            status="completed",
            evidence_count=len(result.evidence),
            error_count=len(result.errors),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        inv.risk_score = report.overall_risk.value
        inv.updated_at = _db_now()
        await session.commit()


async def _run_investigation_pipeline(
    investigation_id: str,
    *,
    redelivered: bool = False,
):
    """Core async investigation pipeline."""
    inv_uuid = UUID(investigation_id)
    logger.info(f"Starting investigation {investigation_id}")

    async with async_session_factory() as session:
        # Load investigation
        result = await session.execute(
            select(Investigation).where(Investigation.id == inv_uuid).with_for_update()
        )
        inv = result.scalar_one_or_none()
        if not inv:
            logger.error(f"Investigation {investigation_id} not found")
            return
        if inv.status == InvestigationStatus.COMPLETED:
            logger.info(
                "Investigation %s is already %s; ignoring duplicate task",
                investigation_id,
                inv.status.value,
            )
            return
        if inv.status == InvestigationStatus.RUNNING:
            if not redelivered and not _running_task_is_stale(inv):
                logger.info(
                    "Investigation %s is already running; ignoring duplicate task",
                    investigation_id,
                )
                return
            logger.warning(
                "Recovering %s investigation %s from its last safe checkpoint",
                "redelivered" if redelivered else "stale",
                investigation_id,
            )
            await session.execute(
                delete(Artifact).where(Artifact.investigation_id == inv_uuid)
            )
            recovery_metadata = dict(inv.case_metadata or {})
            for key in ("error", "progress", "source_status", "structured_report"):
                recovery_metadata.pop(key, None)
            recovery_metadata["recovery"] = {
                "reason": "redelivered" if redelivered else "stale_heartbeat",
                "restarted_at": datetime.now(timezone.utc).isoformat(),
            }
            inv.case_metadata = recovery_metadata
            inv.risk_score = None
            inv.completed_at = None

        # Mark as running
        inv.status = InvestigationStatus.RUNNING
        await _set_progress(
            session,
            inv,
            stage="starting",
            message="Worker accepted the investigation",
            percent=2,
        )

        try:
            # Build target data dict
            target = {
                "name": inv.target_name,
                "aliases": inv.target_aliases or [],
                "username": inv.target_username,
                "usernames": [
                    value
                    for value in (
                        inv.target_username,
                        *((inv.case_metadata or {}).get("additional_usernames", []) or []),
                    )
                    if value
                ],
                "email": inv.target_email,
                "phone": inv.target_phone,
                "employer": (inv.case_metadata or {}).get("employer"),
                "location": (inv.case_metadata or {}).get("location"),
                "depth": inv.depth or "full",
            }
            allowed_sources = _source_scope(inv)
            if allowed_sources is not None:
                _validate_scoped_authorization(inv)

            all_artifacts = []

            # ---- STAGE 1: Identity Expansion ----
            logger.info("Stage 1: Identity expansion...")
            await _set_progress(
                session,
                inv,
                stage="identity",
                message="Expanding authorized identity pivots",
                percent=10,
            )
            identity = IdentityInvestigator(
                # Scoped dashboard cases use only normalized, policy-gated
                # connectors in Stage 1B. Preserve legacy behavior for cases
                # without an explicit source scope.
                allowed_sources=None if allowed_sources is None else set()
            )
            identity_results = await identity.run(
                first_name=target["name"].split()[0]
                if " " in target["name"]
                else target["name"],
                last_name=target["name"].split()[-1] if " " in target["name"] else "",
                domains=[
                    str(value)
                    for value in (inv.case_metadata or {}).get("authorized_domains", [])
                ],
            )
            # Merge discovered identifiers
            if identity_results.get("emails_found"):
                target.setdefault("discovered_emails", []).extend(
                    identity_results["emails_found"]
                )
            if identity_results.get("usernames_found"):
                target.setdefault("discovered_usernames", []).extend(
                    identity_results["usernames_found"]
                )
            if identity_results.get("phones_found"):
                target.setdefault("discovered_phones", []).extend(
                    identity_results["phones_found"]
                )

            # ---- STAGE 1B: Policy-gated person intelligence ----
            await _set_progress(
                session,
                inv,
                stage="person_intelligence",
                message="Collecting selected public sources",
                percent=22,
            )
            person_artifacts = await _collect_person_intelligence(
                inv=inv,
                target=target,
                investigation_id=inv_uuid,
            )
            all_artifacts.extend(person_artifacts)
            inv.case_metadata = {
                **(inv.case_metadata or {}),
                "source_status": target.get("_source_status", []),
            }
            session.add_all(person_artifacts)
            await session.commit()
            logger.info(
                "  Collected %s normalized person-intelligence artifacts",
                len(person_artifacts),
            )

            # ---- STAGE 2: Social Media Discovery ----
            logger.info("Stage 2: Social media discovery...")
            await _set_progress(
                session,
                inv,
                stage="social_profiles",
                message="Correlating public profile evidence",
                percent=42,
            )
            usernames_to_scan = list(
                set(
                    ([target["username"]] if target["username"] else [])
                    + target.get("discovered_usernames", [])
                )
            )
            if usernames_to_scan:
                excluded_social_sources = set(target.get("_expanded_sources", []))
                if allowed_sources is not None:
                    excluded_social_sources.update(
                        {"sherlock", "maigret"} - allowed_sources
                    )
                social = SocialMediaInvestigator(
                    excluded_sources=excluded_social_sources
                )
                social_results = await social.run(usernames_to_scan)
                for acct in social_results:
                    artifact = Artifact(
                        investigation_id=inv_uuid,
                        source=acct.get("source", "social"),
                        source_type="social_media",
                        identifier_type="username",
                        identifier_value=acct.get("username", ""),
                        context=acct,
                        confidence="high" if acct.get("url") else "medium",
                    )
                    all_artifacts.append(artifact)
                    session.add(artifact)
                    # Extract any new emails from profiles
                    if acct.get("email"):
                        target.setdefault("discovered_emails", []).append(acct["email"])
                await session.commit()
                logger.info(f"  Found {len(social_results)} social profiles")

            # ---- STAGE 3: Breach Detection ----
            logger.info("Stage 3: Breach detection...")
            await _set_progress(
                session,
                inv,
                stage="email_and_breach",
                message="Checking authorized email and breach-metadata sources",
                percent=58,
            )
            emails_to_check = list(
                set(
                    ([target["email"]] if target["email"] else [])
                    + target.get("discovered_emails", [])
                )
            )
            # ---- STAGE 3A: Email service footprint ----
            logger.info("Stage 3A: Email service footprint...")
            footprint_results = []
            run_legacy_holehe = (
                allowed_sources is None or "holehe" in allowed_sources
            ) and "holehe" not in target.get("_expanded_sources", [])
            if run_legacy_holehe:
                email_footprint = EmailFootprintInvestigator()
                footprint_results = await email_footprint.run(emails_to_check)
            for item in footprint_results:
                metadata = item.get("metadata", {})
                artifact = Artifact(
                    investigation_id=inv_uuid,
                    source=item.get("source", "holehe"),
                    source_type="service_registration",
                    identifier_type="email",
                    identifier_value=metadata.get("email", ""),
                    context={"evidence": item},
                    confidence=(
                        "high"
                        if item.get("confidence", 0) >= 0.8
                        else "medium"
                        if item.get("confidence", 0) >= 0.6
                        else "low"
                    ),
                )
                all_artifacts.append(artifact)
                session.add(artifact)
            await session.commit()
            logger.info("  Found %s email-service signals", len(footprint_results))

            excluded_breach_sources = set(target.get("_expanded_sources", []))
            if allowed_sources is not None:
                excluded_breach_sources.update(
                    {"hibp", "dehashed", "intelx"} - allowed_sources
                )
            breach = BreachInvestigator()
            breach_results = await breach.run(
                emails=emails_to_check,
                usernames=usernames_to_scan,
                excluded_sources=excluded_breach_sources,
            )
            for source_name, records in breach_results.items():
                for rec in records:
                    artifact = Artifact(
                        investigation_id=inv_uuid,
                        source=source_name,
                        source_type="breach",
                        identifier_type="email",
                        identifier_value=rec.get("email", target.get("email", "")),
                        context=rec,
                        confidence=_breach_confidence(source_name),
                    )
                    all_artifacts.append(artifact)
                    session.add(artifact)
                logger.info(f"  {source_name}: {len(records)} records found")
            await session.commit()

            # ---- STAGE 4: Document / Paste Search ----
            logger.info("Stage 4: Document & paste search...")
            doc_results = []
            if allowed_sources is None:
                docs = DocumentInvestigator()
                doc_results = await docs.run(
                    names=[target["name"]] + target.get("aliases", []),
                    emails=emails_to_check,
                )
            for doc in doc_results:
                artifact = Artifact(
                    investigation_id=inv_uuid,
                    source="document_search",
                    source_type="document",
                    identifier_type=doc.get("type", "unknown"),
                    identifier_value=doc.get("value", ""),
                    context=doc,
                    confidence="medium",
                )
                all_artifacts.append(artifact)
                session.add(artifact)
            await session.commit()

            # ---- STAGE 5: Dark Web (if depth >= deep) ----
            if (
                allowed_sources is None
                and settings.allow_sensitive_pivots
                and target.get("depth") in ("deep", "full")
            ):
                logger.info("Stage 5: Dark web search...")
                darkweb = DarkWebInvestigator()
                darkweb_queries = list(
                    set(
                        [target["name"]]
                        + target.get("aliases", [])
                        + [e for e in emails_to_check if e]
                        + [u for u in usernames_to_scan if u]
                        + [target.get("phone", "")]
                    )
                )
                darkweb_results = await darkweb.run(
                    queries=[q for q in darkweb_queries if q]
                )
                for category, items in darkweb_results.items():
                    for item in items:
                        all_artifacts.append(
                            Artifact(
                                investigation_id=inv_uuid,
                                source=category,
                                source_type="darkweb",
                                identifier_type="mention",
                                identifier_value=item.get("url", ""),
                                context=item,
                                confidence="speculative",
                            )
                        )
                    logger.info(f"  {category}: {len(items)} results")

            # ---- STAGE 6: Geolocation ----
            if (
                allowed_sources is None
                and settings.allow_sensitive_pivots
                and target.get("depth") == "full"
            ):
                logger.info("Stage 6: Geolocation...")
                geo = GeolocationInvestigator()
                geo_results = await geo.run(emails=emails_to_check)
                for loc in geo_results:
                    all_artifacts.append(
                        Artifact(
                            investigation_id=inv_uuid,
                            source="geolocation",
                            source_type="address",
                            identifier_type="location",
                            identifier_value=loc.get("address", ""),
                            context=loc,
                            confidence="medium",
                        )
                    )

            # ---- STAGE 7: Financial / Crypto ----
            if (
                allowed_sources is None
                and settings.allow_sensitive_pivots
                and target.get("depth") == "full"
            ):
                logger.info("Stage 7: Financial/crypto...")
                fin = FinancialInvestigator()
                fin_results = await fin.run(
                    emails=emails_to_check,
                    usernames=usernames_to_scan,
                )
                for crypto in fin_results:
                    all_artifacts.append(
                        Artifact(
                            investigation_id=inv_uuid,
                            source="crypto",
                            source_type="crypto",
                            identifier_type="btc"
                            if crypto.get("type") == "bitcoin"
                            else "eth",
                            identifier_value=crypto.get("address", ""),
                            context=crypto,
                            confidence="speculative",
                        )
                    )

            # ---- STAGE 8: Persist artifacts ----
            await _set_progress(
                session,
                inv,
                stage="persisting_evidence",
                message=f"Saving {len(all_artifacts)} normalized evidence items",
                percent=78,
            )
            for artifact in all_artifacts:
                session.add(artifact)
            await session.commit()

            # ---- STAGE 9: Evidence-linked person report ----
            logger.info("Stage 9: Generating structured person report...")
            await _set_progress(
                session,
                inv,
                stage="reporting",
                message="Generating the evidence-linked report",
                percent=90,
            )
            previous_case_id, previous_evidence = await _previous_report_evidence(
                session,
                inv,
            )
            report = await PersonReportGenerator().generate(
                target=target,
                artifacts=all_artifacts,
                current_case_id=str(inv.id),
                previous_case_id=previous_case_id,
                previous_evidence=previous_evidence,
            )
            inv.case_metadata = {
                **(inv.case_metadata or {}),
                "structured_report": report.model_dump(mode="json"),
            }
            inv.risk_score = report.overall_risk.value
            await session.commit()

            # Mark complete
            inv.status = InvestigationStatus.COMPLETED
            inv.completed_at = _db_now()
            await _set_progress(
                session,
                inv,
                stage="complete",
                message="Report is ready to download",
                percent=100,
            )

            logger.info(
                f"Investigation {investigation_id} COMPLETE — "
                f"Artifacts: {len(all_artifacts)}"
            )

        except Exception as e:
            logger.error(
                "Investigation %s FAILED (%s)",
                investigation_id,
                type(e).__name__,
            )
            await session.rollback()
            inv = await session.get(Investigation, inv_uuid)
            if inv is None:
                raise
            inv.status = InvestigationStatus.FAILED
            inv.case_metadata = {
                **(inv.case_metadata or {}),
                "error": f"{type(e).__name__}: investigation pipeline failed",
            }
            await _set_progress(
                session,
                inv,
                stage="failed",
                message="The investigation stopped with an error",
                percent=(inv.case_metadata.get("progress") or {}).get("percent", 0),
            )
            raise


def _db_now() -> datetime:
    """Return naive UTC for the existing TIMESTAMP WITHOUT TIME ZONE columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _running_task_is_stale(inv: Investigation) -> bool:
    """Return true when a running case has stopped updating its heartbeat."""
    progress = (inv.case_metadata or {}).get("progress") or {}
    heartbeat: datetime | None = None
    raw_heartbeat = progress.get("updated_at")
    if raw_heartbeat:
        try:
            heartbeat = datetime.fromisoformat(
                str(raw_heartbeat).replace("Z", "+00:00")
            )
        except ValueError:
            heartbeat = None
    if heartbeat is None:
        heartbeat = inv.updated_at or inv.created_at
    if heartbeat is None:
        return True
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    stale_after = timedelta(seconds=max(60, settings.running_task_stale_seconds))
    return datetime.now(timezone.utc) - heartbeat >= stale_after


def _source_scope(inv: Investigation) -> set[str] | None:
    """Return an explicit source allowlist, or None for legacy unscoped cases."""
    sources = (inv.case_metadata or {}).get("permitted_sources")
    if not isinstance(sources, list):
        return None
    return {str(source).strip().lower() for source in sources if str(source).strip()}


def _validate_scoped_authorization(inv: Investigation) -> None:
    """Fail closed before any external connector runs for a scoped case."""
    metadata = inv.case_metadata or {}
    if not metadata.get("authorization_confirmed"):
        raise PermissionError("Written authorization is not confirmed")
    if not str(metadata.get("authorization_reference") or "").strip():
        raise PermissionError("Authorization reference is missing")
    raw_expiry = metadata.get("authorization_expires_at")
    try:
        expiry = datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise PermissionError("Authorization expiry is invalid") from exc
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise PermissionError("Authorization has expired")


async def _set_progress(
    session: AsyncSession,
    inv: Investigation,
    *,
    stage: str,
    message: str,
    percent: int,
) -> None:
    """Persist dashboard-visible progress with a JSON reassignment."""
    inv.case_metadata = {
        **(inv.case_metadata or {}),
        "progress": {
            "stage": stage,
            "message": message,
            "percent": max(0, min(100, int(percent))),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    inv.updated_at = _db_now()
    await session.commit()


async def _previous_report_evidence(
    session: AsyncSession,
    inv: Investigation,
) -> tuple[str | None, list[Evidence]]:
    """Load the latest comparable report without treating absence as evidence.

    Comparison is explicit opt-in. A prior case is comparable only when the
    normalized target name, preferred operator-supplied identifier, unexpired
    authorization reference, purpose, and source scope match. Malformed or
    legacy ledgers are skipped rather than weakening the current report.
    """
    metadata = inv.case_metadata or {}
    if not metadata.get("compare_previous_cases"):
        return None, []
    if not metadata.get("authorization_confirmed"):
        return None, []

    if inv.target_email:
        identifier_match = (
            func.lower(Investigation.target_email)
            == inv.target_email.strip().casefold()
        )
    elif inv.target_username:
        identifier_match = (
            func.lower(Investigation.target_username)
            == inv.target_username.strip().casefold()
        )
    else:
        return None, []

    result = await session.execute(
        select(Investigation)
        .options(noload(Investigation.artifacts))
        .where(
            Investigation.id != inv.id,
            Investigation.status == InvestigationStatus.COMPLETED,
            func.lower(Investigation.target_name)
            == inv.target_name.strip().casefold(),
            identifier_match,
        )
        .order_by(
            Investigation.completed_at.desc().nullslast(),
            Investigation.created_at.desc(),
        )
        .limit(25)
    )
    candidates = result.scalars().all()
    current_reference = str(metadata.get("authorization_reference") or "").strip()
    current_purpose = " ".join(
        str(metadata.get("lawful_purpose") or "").split()
    ).casefold()
    current_sources = {
        str(source).strip().casefold()
        for source in metadata.get("permitted_sources", [])
        if str(source).strip()
    }
    if not current_reference or not current_purpose or not current_sources:
        return None, []

    for previous in candidates:
        previous_metadata = previous.case_metadata or {}
        if not previous_metadata.get("authorization_confirmed"):
            continue
        if (
            str(previous_metadata.get("authorization_reference") or "").strip()
            != current_reference
        ):
            continue
        previous_purpose = " ".join(
            str(previous_metadata.get("lawful_purpose") or "").split()
        ).casefold()
        if previous_purpose != current_purpose:
            continue
        previous_sources = {
            str(source).strip().casefold()
            for source in previous_metadata.get("permitted_sources", [])
            if str(source).strip()
        }
        if previous_sources != current_sources:
            continue
        try:
            previous_expiry = datetime.fromisoformat(
                str(
                    previous_metadata.get("authorization_expires_at") or ""
                ).replace("Z", "+00:00")
            )
        except ValueError:
            continue
        if previous_expiry.tzinfo is None:
            previous_expiry = previous_expiry.replace(tzinfo=timezone.utc)
        if previous_expiry <= datetime.now(timezone.utc):
            continue

        structured_report = previous_metadata.get("structured_report")
        if not isinstance(structured_report, dict):
            continue
        ledger = structured_report.get("evidence_ledger")
        if not isinstance(ledger, list):
            continue

        evidence = []
        malformed = False
        for payload in ledger:
            if not isinstance(payload, dict):
                malformed = True
                continue
            try:
                evidence.append(
                    Evidence.model_validate(redact_sensitive(payload))
                )
            except Exception:
                malformed = True
        if malformed:
            logger.warning(
                "Skipping temporal baseline %s because its evidence ledger "
                "is malformed",
                previous.id,
            )
            continue
        return str(previous.id), evidence
    return None, []


def _breach_confidence(source: str) -> str:
    return {"hibp": "high", "dehashed": "high", "intelx": "medium"}.get(
        source, "medium"
    )


async def _collect_person_intelligence(
    *,
    inv: Investigation,
    target: dict,
    investigation_id: UUID,
) -> list[Artifact]:
    """Run approved normalized connectors and return persistence-safe artifacts."""
    metadata = inv.case_metadata or {}
    if not metadata.get("authorization_confirmed"):
        logger.info(
            "Skipping expanded person intelligence: authorization is not confirmed"
        )
        return []

    authorization_reference = str(
        metadata.get("authorization_reference")
        or settings.authorization_reference
        or ""
    ).strip()
    if not authorization_reference:
        logger.warning(
            "Skipping expanded person intelligence: authorization reference is missing"
        )
        return []

    expires_at_raw = metadata.get("authorization_expires_at")
    try:
        expires_at = datetime.fromisoformat(str(expires_at_raw).replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        logger.warning(
            "Skipping expanded person intelligence: valid authorization expiry is missing"
        )
        return []

    configured_sources = {
        source.strip().lower()
        for source in settings.person_osint_sources.split(",")
        if source.strip()
    }
    requested_sources = metadata.get("permitted_sources")
    if isinstance(requested_sources, list):
        configured_sources &= {
            str(source).strip().lower() for source in requested_sources
        }
    target["_expanded_sources"] = sorted(configured_sources)

    names = [target["name"], *target.get("aliases", [])]
    usernames = [
        value
        for value in [
            target.get("username"),
            *metadata.get("additional_usernames", []),
            *target.get("discovered_usernames", []),
        ]
        if value
    ]
    emails = [
        value
        for value in [target.get("email"), *target.get("discovered_emails", [])]
        if value
    ]
    person_target = InvestigationTarget(
        name=names[0],
        aliases=names[1:],
        usernames=usernames,
        emails=emails,
        domains=[str(value) for value in metadata.get("authorized_domains", [])],
        employer=metadata.get("employer"),
        location=metadata.get("location"),
        lawful_purpose=str(
            metadata.get("lawful_purpose") or "Authorized defensive OSINT review"
        ),
        authorization_confirmed=True,
    )
    policy = CollectionPolicy(
        authorization_reference=authorization_reference,
        purpose=person_target.lawful_purpose,
        expires_at=expires_at,
        permitted_sources=frozenset(configured_sources),
        infrastructure_enrichment=bool(
            settings.allow_infrastructure_enrichment
            and metadata.get("allow_infrastructure_enrichment")
        ),
    )
    investigator = PersonIntelligenceInvestigator(policy)
    results = await investigator.collect_plan(
        target=person_target,
        authorized_ips=[str(value) for value in metadata.get("authorized_ips", [])],
        concurrency=settings.max_osint_concurrency,
    )

    artifacts: list[Artifact] = []
    source_status = {
        source: {
            "source": source,
            "status": "not_queried",
            "evidence_count": 0,
        }
        for source in configured_sources
    }
    for request, result in results:
        status = source_status[request.source]
        status["evidence_count"] += len(result.evidence)
        if result.evidence:
            status["status"] = "evidence_collected"
        elif result.errors and status["status"] != "evidence_collected":
            status["status"] = "unavailable"
        elif status["status"] == "not_queried":
            status["status"] = "no_results"
        if result.errors:
            status["reason_code"] = _connector_status_reason(result.errors)
            status["detail"] = _connector_status_detail(
                request.source,
                result.errors,
            )
            logger.warning(
                "%s reported %s collection error(s)",
                result.connector,
                len(result.errors),
            )
        for evidence in result.evidence:
            artifacts.append(
                Artifact(
                    investigation_id=investigation_id,
                    source=evidence.source,
                    source_type=evidence.type,
                    identifier_type=request.identifier_type,
                    identifier_value=request.identifier,
                    context={
                        "evidence": redact_sensitive(evidence.model_dump(mode="json"))
                    },
                    confidence=_confidence_label(evidence.confidence),
                )
            )
    target["_source_status"] = [
        source_status[source] for source in sorted(source_status)
    ]
    return artifacts


def _confidence_label(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def _connector_status_reason(errors: list[str]) -> str:
    """Classify raw connector errors into an allow-listed persistence value."""
    normalized = " ".join(errors).casefold()
    if "not configured" in normalized:
        return "missing_configuration"
    if "not installed" in normalized or "not on path" in normalized:
        return "connector_unavailable"
    if "timed out" in normalized or "timeout" in normalized:
        return "timeout"
    if any(token in normalized for token in ("rate limit", "too many requests", "429")):
        return "rate_limited"
    if any(
        token in normalized
        for token in ("unauthorized", "forbidden", "401", "403", "authentication")
    ):
        return "authentication_rejected"
    if "invalid" in normalized:
        return "invalid_request_or_response"
    return "request_failed"


def _connector_status_detail(source: str, errors: list[str]) -> str:
    """Convert connector failures into safe, actionable coverage notes.

    Raw provider and CLI errors can contain request details or credentials, so
    only a small allow-listed set of failure categories is persisted.
    """

    display_name = {
        "github": "GitHub",
        "hibp": "HIBP",
        "spiderfoot": "SpiderFoot",
    }.get(source.casefold(), source.replace("_", " ").title())
    reason = _connector_status_reason(errors)
    templates = {
        "missing_configuration": (
            f"{display_name} configuration or credentials are not configured."
        ),
        "connector_unavailable": (
            f"{display_name} local connector is not installed or available."
        ),
        "timeout": (
            f"{display_name} did not complete before the connector timeout."
        ),
        "rate_limited": (
            f"{display_name} was unavailable because of provider rate limiting."
        ),
        "authentication_rejected": (
            f"{display_name} rejected the configured provider credentials."
        ),
        "invalid_request_or_response": (
            f"{display_name} rejected the target or returned an invalid response."
        ),
        "request_failed": f"{display_name} could not complete this collection request.",
    }
    return templates[reason]


@app.task(name="deepvault.periodic_healthcheck")
def periodic_healthcheck():
    """Periodic task to ensure all services are operational."""
    logger.debug("Healthcheck OK")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
@worker_ready.connect
def on_worker_ready(**kwargs):
    asyncio.run(create_tables())
    logger.info("WorldAtlas orchestrator ready.")


@worker_shutdown.connect
def on_worker_shutdown(**kwargs):
    logger.info("WorldAtlas orchestrator shutting down.")
