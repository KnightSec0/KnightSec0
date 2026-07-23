"""
DeepVault Orchestrator — Celery entrypoint and task definitions.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from celery import Celery
from celery.signals import worker_ready, worker_shutdown
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

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
from intelligence.models import InvestigationTarget
from intelligence.policy import CollectionPolicy
from intelligence.redaction import redact_sensitive
from reporting.person_report import PersonReportGenerator

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
engine = create_async_engine(settings.db_url, echo=False, pool_size=10, max_overflow=20)
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
                "email": inv.target_email,
                "phone": inv.target_phone,
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
            report = await PersonReportGenerator().generate(
                target=target,
                artifacts=all_artifacts,
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
        for value in [target.get("username"), *target.get("discovered_usernames", [])]
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


@app.task(name="deepvault.periodic_healthcheck")
def periodic_healthcheck():
    """Periodic task to ensure all services are operational."""
    logger.debug("Healthcheck OK")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
@worker_ready.connect
def on_worker_ready(**kwargs):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(create_tables())
    logger.info("DeepVault orchestrator ready.")


@worker_shutdown.connect
def on_worker_shutdown(**kwargs):
    logger.info("DeepVault orchestrator shutting down.")
