"""Transform wrappers around DeepVault's normalized first-party connectors."""

from __future__ import annotations

from connectors import (
    HoleheConnector,
    MaigretConnector,
    SherlockConnector,
    SpiderFootConnector,
)
from intelligence.models import ConnectorResult

from ..base import (
    TransformAdapter,
    TransformContext,
    TransformEntity,
    TransformSpec,
)


class _ConnectorTransform(TransformAdapter):
    connector_class = None

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        connector = self.connector_class()
        return await connector.search(entity.value)


class SpiderFootTransform(_ConnectorTransform):
    connector_class = SpiderFootConnector
    spec = TransformSpec(
        name="spiderfoot",
        title="SpiderFoot passive scan",
        accepted_entity_types={"username", "email", "domain", "hostname", "ip"},
        produced_entity_types={
            "public_profile",
            "email_observation",
            "domain_observation",
            "infrastructure_observation",
            "web_observation",
        },
        passive=True,
        priority="p0",
        independence_group="spiderfoot",
        description=(
            "Run an explicitly configured passive SpiderFoot scan and import "
            "normalized, non-sensitive observations."
        ),
    )


class SherlockTransform(_ConnectorTransform):
    connector_class = SherlockConnector
    spec = TransformSpec(
        name="sherlock",
        title="Sherlock username discovery",
        accepted_entity_types={"username"},
        produced_entity_types={"public_profile"},
        passive=True,
        priority="p0",
        independence_group="sherlock-catalog",
    )


class MaigretTransform(_ConnectorTransform):
    connector_class = MaigretConnector
    spec = TransformSpec(
        name="maigret",
        title="Maigret username discovery",
        accepted_entity_types={"username"},
        produced_entity_types={"public_profile"},
        passive=True,
        priority="p0",
        independence_group="maigret-catalog",
    )


class HoleheTransform(_ConnectorTransform):
    connector_class = HoleheConnector
    spec = TransformSpec(
        name="holehe",
        title="Holehe service-presence signals",
        accepted_entity_types={"email"},
        produced_entity_types={"service"},
        passive=True,
        priority="p0",
        independence_group="holehe",
    )
