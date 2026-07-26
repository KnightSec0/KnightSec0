"""Bounded transform execution with authorization and provenance enforcement."""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlsplit

from intelligence.models import ConnectorResult

from .base import TransformContext, TransformEntity
from .budgets import BudgetTracker, TransformBudgets
from .registry import TransformRegistry


def _normalized_domain(value: str) -> str:
    candidate = value.strip().casefold().rstrip(".")
    if "://" in candidate:
        candidate = (urlsplit(candidate).hostname or "").casefold().rstrip(".")
    return candidate


class TransformRunner:
    def __init__(
        self,
        registry: TransformRegistry,
        budgets: TransformBudgets,
    ) -> None:
        self.registry = registry
        self.budgets = budgets
        self._semaphore = asyncio.Semaphore(budgets.max_parallel_transforms)

    def _authorize(
        self,
        *,
        transform_name: str,
        entity: TransformEntity,
        context: TransformContext,
    ):
        adapter = self.registry.get(transform_name)
        spec = adapter.spec
        if transform_name not in context.permitted_transforms:
            raise PermissionError(
                f"Transform is outside the approved source scope: {transform_name}"
            )
        if entity.type not in spec.accepted_entity_types:
            raise ValueError(
                f"{transform_name} does not accept entity type {entity.type}"
            )
        if spec.authenticated and not context.allow_authenticated_transforms:
            raise PermissionError("Authenticated transforms are disabled")
        if not spec.passive:
            if not context.allow_infrastructure_enrichment:
                raise PermissionError("Active transforms require separate consent")
            if entity.type in {"domain", "hostname", "url"}:
                domain = _normalized_domain(entity.value)
                if not any(
                    domain == allowed or domain.endswith(f".{allowed}")
                    for allowed in context.authorized_domains
                ):
                    raise PermissionError("Domain is outside the authorized scope")
            elif entity.type == "ip":
                ip = str(ipaddress.ip_address(entity.value))
                if ip not in context.authorized_ips:
                    raise PermissionError("IP is outside the authorized scope")
            else:
                raise PermissionError(
                    "Active transforms require an explicitly authorized asset"
                )
        return adapter

    async def run(
        self,
        *,
        transform_name: str,
        entity: TransformEntity,
        context: TransformContext,
        current_graph_nodes: int = 0,
    ) -> ConnectorResult:
        adapter = self._authorize(
            transform_name=transform_name,
            entity=entity,
            context=context,
        )
        tracker = BudgetTracker(
            self.budgets,
            current_graph_nodes=current_graph_nodes,
        )
        tracker.authorize_depth(context.pivot_depth)
        async with self._semaphore:
            result = await asyncio.wait_for(
                adapter.execute(entity, context),
                timeout=self.budgets.transform_timeout,
            )
        retained = tracker.retain(result.evidence)
        enriched = []
        for item in retained:
            evidence_ids = list(
                dict.fromkeys([*item.evidence_ids, *entity.evidence_ids])
            )
            metadata = {
                **item.metadata,
                "transform": transform_name,
                "input_entity_type": entity.type,
                "pivot_depth": context.pivot_depth,
            }
            enriched.append(
                item.model_copy(
                    update={
                        "authorization_reference": context.authorization_reference,
                        "evidence_ids": evidence_ids,
                        "independence_group": (
                            item.independence_group
                            or adapter.spec.independence_group
                            or adapter.spec.name
                        ),
                        "metadata": metadata,
                    }
                )
            )
        errors = list(result.errors)
        if len(result.evidence) > len(retained):
            errors.append("Transform result budget truncated additional observations")
        return result.model_copy(update={"evidence": enriched, "errors": errors})
