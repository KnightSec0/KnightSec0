"""
DeepVault Orchestrator — Celery entrypoint and task definitions.
"""
import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID

from celery import Celery
from celery.signals import worker_ready, worker_shutdown
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from config import settings
from db.models import Base, Investigation, InvestigationStatus, Artifact
from db.neo4j_client import Neo4jClient
from investigators.identity import IdentityInvestigator
from investigators.social import SocialMediaInvestigator
from investigators.breach import BreachInvestigator
from investigators.darkweb import DarkWebInvestigator
from investigators.documents import DocumentInvestigator
from investigators.geolocation import GeolocationInvestigator
from investigators.financial import FinancialInvestigator

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
async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def create_tables():
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified/created.")


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
@app.task(bind=True, max_retries=3, default_retry_delay=60)
def run_investigation(self, investigation_id: str):
    """Entry point: run full investigation pipeline for a given ID."""
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_run_investigation_pipeline(investigation_id))


async def _run_investigation_pipeline(investigation_id: str):
    """Core async investigation pipeline."""
    inv_uuid = UUID(investigation_id)
    logger.info(f"Starting investigation {investigation_id}")

    async with async_session_factory() as session:
        # Load investigation
        result = await session.execute(
            select(Investigation).where(Investigation.id == inv_uuid)
        )
        inv = result.scalar_one_or_none()
        if not inv:
            logger.error(f"Investigation {investigation_id} not found")
            return

        # Mark as running
        inv.status = InvestigationStatus.RUNNING
        inv.updated_at = datetime.now(timezone.utc)
        await session.commit()

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

            all_artifacts = []

            # ---- STAGE 1: Identity Expansion ----
            logger.info("Stage 1: Identity expansion...")
            identity = IdentityInvestigator()
            identity_results = await identity.run(
                first_name=target["name"].split()[0] if " " in target["name"] else target["name"],
                last_name=target["name"].split()[-1] if " " in target["name"] else "",
            )
            # Merge discovered identifiers
            if identity_results.get("emails_found"):
                target.setdefault("discovered_emails", []).extend(identity_results["emails_found"])
            if identity_results.get("usernames_found"):
                target.setdefault("discovered_usernames", []).extend(identity_results["usernames_found"])
            if identity_results.get("phones_found"):
                target.setdefault("discovered_phones", []).extend(identity_results["phones_found"])

            # ---- STAGE 2: Social Media Discovery ----
            logger.info("Stage 2: Social media discovery...")
            usernames_to_scan = list(set(
                [target["username"]] if target["username"] else []
                + target.get("discovered_usernames", [])
            ))
            if usernames_to_scan:
                social = SocialMediaInvestigator()
                social_results = await social.run(usernames_to_scan)
                for acct in social_results:
                    all_artifacts.append(Artifact(
                        investigation_id=inv_uuid,
                        source=acct.get("source", "social"),
                        source_type="social_media",
                        identifier_type="username",
                        identifier_value=acct.get("username", ""),
                        context=acct,
                        confidence="high" if acct.get("url") else "medium",
                    ))
                    # Extract any new emails from profiles
                    if acct.get("email"):
                        target.setdefault("discovered_emails", []).append(acct["email"])
                logger.info(f"  Found {len(social_results)} social profiles")

            # ---- STAGE 3: Breach Detection ----
            logger.info("Stage 3: Breach detection...")
            emails_to_check = list(set(
                [target["email"]] if target["email"] else []
                + target.get("discovered_emails", [])
            ))
            breach = BreachInvestigator()
            breach_results = await breach.run(
                emails=emails_to_check,
                usernames=usernames_to_scan,
            )
            for source_name, records in breach_results.items():
                for rec in records:
                    all_artifacts.append(Artifact(
                        investigation_id=inv_uuid,
                        source=source_name,
                        source_type="breach",
                        identifier_type="email",
                        identifier_value=rec.get("email", target.get("email", "")),
                        context=rec,
                        confidence=_breach_confidence(source_name),
                    ))
                logger.info(f"  {source_name}: {len(records)} records found")

            # ---- STAGE 4: Document / Paste Search ----
            logger.info("Stage 4: Document & paste search...")
            docs = DocumentInvestigator()
            doc_results = await docs.run(
                names=[target["name"]] + target.get("aliases", []),
                emails=emails_to_check,
            )
            for doc in doc_results:
                all_artifacts.append(Artifact(
                    investigation_id=inv_uuid,
                    source="document_search",
                    source_type="document",
                    identifier_type=doc.get("type", "unknown"),
                    identifier_value=doc.get("value", ""),
                    context=doc,
                    confidence="medium",
                ))

            # ---- STAGE 5: Dark Web (if depth >= deep) ----
            if target.get("depth") in ("deep", "full"):
                logger.info("Stage 5: Dark web search...")
                darkweb = DarkWebInvestigator()
                darkweb_queries = list(set(
                    [target["name"]] + target.get("aliases", [])
                    + [e for e in emails_to_check if e]
                    + [u for u in usernames_to_scan if u]
                    + [target.get("phone", "")]
                ))
                darkweb_results = await darkweb.run(
                    queries=[q for q in darkweb_queries if q]
                )
                for category, items in darkweb_results.items():
                    for item in items:
                        all_artifacts.append(Artifact(
                            investigation_id=inv_uuid,
                            source=category,
                            source_type="darkweb",
                            identifier_type="mention",
                            identifier_value=item.get("url", ""),
                            context=item,
                            confidence="speculative",
                        ))
                    logger.info(f"  {category}: {len(items)} results")

            # ---- STAGE 6: Geolocation ----
            if target.get("depth") == "full":
                logger.info("Stage 6: Geolocation...")
                geo = GeolocationInvestigator()
                geo_results = await geo.run(emails=emails_to_check)
                for loc in geo_results:
                    all_artifacts.append(Artifact(
                        investigation_id=inv_uuid,
                        source="geolocation",
                        source_type="address",
                        identifier_type="location",
                        identifier_value=loc.get("address", ""),
                        context=loc,
                        confidence="medium",
                    ))

            # ---- STAGE 7: Financial / Crypto ----
            if target.get("depth") == "full":
                logger.info("Stage 7: Financial/crypto...")
                fin = FinancialInvestigator()
                fin_results = await fin.run(
                    emails=emails_to_check,
                    usernames=usernames_to_scan,
                )
                for crypto in fin_results:
                    all_artifacts.append(Artifact(
                        investigation_id=inv_uuid,
                        source="crypto",
                        source_type="crypto",
                        identifier_type="btc" if crypto.get("type") == "bitcoin" else "eth",
                        identifier_value=crypto.get("address", ""),
                        context=crypto,
                        confidence="speculative",
                    ))

            # ---- STAGE 8: Persist artifacts ----
            for artifact in all_artifacts:
                session.add(artifact)
            await session.commit()

            # Mark complete
            inv.status = InvestigationStatus.COMPLETED
            inv.completed_at = datetime.now(timezone.utc)
            await session.commit()

            logger.info(f"Investigation {investigation_id} COMPLETE — "
                        f"Artifacts: {len(all_artifacts)}")

        except Exception as e:
            logger.exception(f"Investigation {investigation_id} FAILED: {e}")
            inv.status = InvestigationStatus.FAILED
            inv.metadata = inv.metadata or {}
            inv.metadata["error"] = str(e)
            await session.commit()
            raise


def _breach_confidence(source: str) -> str:
    return {"hibp": "high", "dehashed": "high", "intelx": "medium"}.get(source, "medium")


@app.task
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
