import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from main import _connector_status_detail, _connector_status_reason


class ConnectorStatusDetailTests(unittest.TestCase):
    def test_missing_configuration_is_actionable_without_raw_error(self):
        detail = _connector_status_detail(
            "hibp",
            ["HIBP_API_KEY is not configured"],
        )

        self.assertEqual(
            detail,
            "HIBP configuration or credentials are not configured.",
        )
        self.assertNotIn("API_KEY", detail)

    def test_unknown_error_is_not_persisted(self):
        detail = _connector_status_detail(
            "example",
            ["request failed with token=must-not-survive at a private endpoint"],
        )

        self.assertEqual(
            detail,
            "Example could not complete this collection request.",
        )
        self.assertNotIn("must-not-survive", detail)

    def test_timeout_and_rate_limit_are_distinguished(self):
        self.assertIn(
            "timeout",
            _connector_status_detail("maigret", ["process timed out"]).casefold(),
        )
        self.assertIn(
            "rate limiting",
            _connector_status_detail("hunter", ["HTTP 429"]).casefold(),
        )
        self.assertEqual(
            _connector_status_reason(["HTTP 429"]),
            "rate_limited",
        )


if __name__ == "__main__":
    unittest.main()
