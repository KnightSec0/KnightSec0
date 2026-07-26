# ruff: noqa: E402

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from connectors.person_sources import (
    SpiderFootConnector,
    _spiderfoot_evidence,
    _spiderfoot_start_id,
    _spiderfoot_status,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.text = json.dumps(payload)
        self.content = self.text.encode()

    def json(self):
        return self.payload

    def raise_for_status(self):
        return None


class FakeClient:
    def __init__(self):
        self.statuses = iter(["STARTING", "FINISHED"])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, **kwargs):
        del kwargs
        if url.endswith("/startscan"):
            return FakeResponse(["SUCCESS", "SCAN-1"])
        return FakeResponse(
            [
                {
                    "data": "https://github.com/alice",
                    "event_type": "SOCIAL_MEDIA",
                    "module": "sfp_accounts",
                    "source_data": "alice",
                    "false_positive": 0,
                    "last_seen": "2026-07-26 10:00:00",
                },
                {
                    "data": "must-not-survive",
                    "event_type": "PASSWORD_COMPROMISED",
                    "module": "unsafe",
                    "false_positive": 0,
                },
            ]
        )

    async def get(self, url, **kwargs):
        del url, kwargs
        return FakeResponse(
            ["name", "target", "created", "started", "ended", next(self.statuses), {}]
        )


class SpiderFootConnectorTests(unittest.TestCase):
    def test_start_status_and_event_parsers_fail_closed(self):
        self.assertEqual(_spiderfoot_start_id(["SUCCESS", "SCAN-1"]), "SCAN-1")
        self.assertIsNone(_spiderfoot_start_id(["ERROR", "bad target"]))
        self.assertEqual(
            _spiderfoot_status(["n", "t", "c", "s", "e", "FINISHED"]),
            "FINISHED",
        )
        evidence = _spiderfoot_evidence(
            [
                {
                    "data": "https://github.com/alice",
                    "event_type": "SOCIAL_MEDIA",
                    "module": "sfp_accounts",
                    "false_positive": 0,
                },
                {
                    "data": "secret",
                    "event_type": "PASSWORD_COMPROMISED",
                    "module": "unsafe",
                    "false_positive": 0,
                },
                {
                    "data": "https://false.example/alice",
                    "event_type": "SOCIAL_MEDIA",
                    "module": "sfp_accounts",
                    "false_positive": 1,
                },
            ],
            scan_id="SCAN-1",
            target="alice",
        )
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].type, "social_profile")
        self.assertNotIn("secret", evidence[0].model_dump_json())

    def test_connector_waits_and_imports_safe_results(self):
        with (
            patch(
                "connectors.person_sources.settings.spiderfoot_url",
                "http://spiderfoot:5001",
            ),
            patch(
                "connectors.person_sources.settings.spiderfoot_poll_interval",
                0.001,
            ),
            patch(
                "connectors.person_sources.httpx.AsyncClient",
                return_value=FakeClient(),
            ),
        ):
            result = asyncio.run(SpiderFootConnector().search("alice"))

        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.evidence[0].value, "https://github.com/alice")
        self.assertEqual(
            result.evidence[0].metadata["spiderfoot_scan_id"],
            "SCAN-1",
        )


if __name__ == "__main__":
    unittest.main()
