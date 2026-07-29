# ruff: noqa: E402

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.models import ConnectorResult, Evidence
from transforms.base import (
    TransformAdapter,
    TransformContext,
    TransformEntity,
    TransformSpec,
)
from transforms.budgets import BudgetExceeded, TransformBudgets
from transforms.planner import TransformPlanner
from transforms.registry import TransformRegistry
from transforms.runner import TransformRunner
from transforms.adapters.cli_tools import BlackbirdTransform
from connectors.cli import CLIResult


class FakeAdapter(TransformAdapter):
    spec = TransformSpec(
        name="fake",
        title="Fake passive transform",
        accepted_entity_types={"username"},
        produced_entity_types={"public_profile"},
        passive=True,
        priority="p0",
        independence_group="shared-catalog",
    )

    async def execute(self, entity, context):
        del context
        return ConnectorResult(
            connector=self.spec.name,
            evidence=[
                Evidence(
                    id=f"EVID-{index}",
                    type="social_profile",
                    value=f"https://example.test/{entity.value}/{index}",
                    source=self.spec.name,
                )
                for index in range(3)
            ],
        )


class ActiveAdapter(FakeAdapter):
    spec = TransformSpec(
        name="active",
        title="Active authorized-domain transform",
        accepted_entity_types={"domain"},
        produced_entity_types={"web_observation"},
        passive=False,
        priority="p2",
    )


def context(**overrides):
    payload = {
        "case_id": "CASE-1",
        "authorization_reference": "AUTH-1",
        "lawful_purpose": "Consent-based defensive assessment",
        "authorization_expires_at": datetime.now(timezone.utc)
        + timedelta(hours=1),
        "permitted_transforms": {"fake"},
        "authorized_domains": {"example.com"},
        "pivot_depth": 1,
    }
    payload.update(overrides)
    return TransformContext(**payload)


class TransformEngineTests(unittest.TestCase):
    def registry(self):
        registry = TransformRegistry()
        registry.register(FakeAdapter())
        registry.register(ActiveAdapter())
        return registry

    def test_runner_enriches_provenance_and_applies_result_budget(self):
        runner = TransformRunner(
            self.registry(),
            TransformBudgets(max_results_per_transform=2),
        )
        result = asyncio.run(
            runner.run(
                transform_name="fake",
                entity=TransformEntity(
                    type="username",
                    value="alice",
                    evidence_ids=["EVID-PARENT"],
                ),
                context=context(),
            )
        )

        self.assertEqual(len(result.evidence), 2)
        self.assertIn("truncated", " ".join(result.errors))
        for item in result.evidence:
            self.assertEqual(item.authorization_reference, "AUTH-1")
            self.assertEqual(item.evidence_ids, ["EVID-PARENT"])
            self.assertEqual(item.independence_group, "shared-catalog")
            self.assertEqual(item.metadata["transform"], "fake")
            self.assertEqual(item.metadata["pivot_depth"], 1)

    def test_runner_rejects_unapproved_and_out_of_scope_active_transform(self):
        runner = TransformRunner(self.registry(), TransformBudgets())
        entity = TransformEntity(type="domain", value="outside.test")
        with self.assertRaisesRegex(PermissionError, "outside the approved"):
            asyncio.run(
                runner.run(
                    transform_name="active",
                    entity=entity,
                    context=context(permitted_transforms={"fake"}),
                )
            )
        with self.assertRaisesRegex(PermissionError, "outside the authorized"):
            asyncio.run(
                runner.run(
                    transform_name="active",
                    entity=entity,
                    context=context(
                        permitted_transforms={"active"},
                        allow_infrastructure_enrichment=True,
                    ),
                )
            )
        with self.assertRaisesRegex(PermissionError, "separate consent"):
            asyncio.run(
                runner.run(
                    transform_name="active",
                    entity=TransformEntity(type="domain", value="example.com"),
                    context=context(permitted_transforms={"active"}),
                )
            )

    def test_runner_enforces_pivot_depth(self):
        runner = TransformRunner(
            self.registry(),
            TransformBudgets(max_pivot_depth=1),
        )
        with self.assertRaises(BudgetExceeded):
            asyncio.run(
                runner.run(
                    transform_name="fake",
                    entity=TransformEntity(type="username", value="alice"),
                    context=context(pivot_depth=2),
                )
            )

    def test_planner_returns_choices_without_execution(self):
        planner = TransformPlanner(self.registry())
        choices = planner.choices(
            TransformEntity(type="username", value="alice"),
            permitted_transforms={"fake", "active"},
            pivot_depth=1,
        )
        self.assertEqual([choice.transform for choice in choices], ["fake"])
        self.assertEqual(choices[0].execution_mode, "analyst_confirmation_required")

    def test_blackbird_imports_json_observations_without_ai(self):
        async def fake_run_cli(
            args,
            *,
            timeout,
            cwd=None,
            max_output_bytes,
        ):
            del timeout, max_output_bytes
            self.assertNotIn("--ai", args)
            self.assertEqual(Path(cwd).resolve(), tool_root.resolve())
            output = tool_root / "results" / "alice" / "alice.json"
            output.parent.mkdir(parents=True)
            output.write_text(
                '[{"name":"Example","url":"https://example.test/alice"},'
                '{"name":"Missing","url":"https://missing.test/alice",'
                '"exists":false},'
                '{"name":"Partial","url":"https://example.test/malice",'
                '"status":"found"}]',
                encoding="utf-8",
            )
            return CLIResult(
                args=args,
                returncode=0,
                stdout="",
                stderr="",
                duration_ms=10,
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            tool_root = Path(temp_dir)
            script = tool_root / "blackbird.py"
            script.write_text("# test fixture\n", encoding="utf-8")
            with (
                patch.dict(
                    os.environ,
                    {"BLACKBIRD_PATH": str(script)},
                    clear=False,
                ),
                patch(
                    "transforms.adapters.cli_tools.run_cli",
                    side_effect=fake_run_cli,
                ),
                patch(
                    "transforms.adapters.cli_tools._tool",
                    return_value=None,
                ),
            ):
                result = asyncio.run(
                    BlackbirdTransform().execute(
                        TransformEntity(type="username", value="alice"),
                        context(),
                    )
                )

        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(
            result.evidence[0].value,
            "https://example.test/alice",
        )


if __name__ == "__main__":
    unittest.main()
