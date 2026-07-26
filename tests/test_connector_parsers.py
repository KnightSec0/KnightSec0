# ruff: noqa: E402

import asyncio
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from connectors.cli import CLIResult
from connectors.holehe import _positive_service
from connectors.maigret import MaigretConnector, _is_claimed
from connectors.sherlock import SherlockConnector


class ConnectorParserTests(unittest.TestCase):
    def test_holehe_ignores_summary_legend_and_keeps_service_domains(self):
        self.assertIsNone(_positive_service("[+] Email used, [-] Email not used"))
        self.assertIsNone(_positive_service("[+] email"))
        self.assertEqual(
            _positive_service("\x1b[32m[+] en.gravatar.com\x1b[0m"),
            "en.gravatar.com",
        )

    def test_maigret_uses_hostname_not_nested_site_configuration(self):
        async def fake_run_cli(args, *, timeout, cwd=None):
            del timeout, cwd
            output_dir = Path(args[args.index("--folderoutput") + 1])
            profile_url = "https://www.instagram.com/alice/"
            payload = {
                "Instagram": {
                    "username": "alice",
                    "url_main": "https://www.instagram.com/",
                    "url_user": profile_url,
                    "status": {
                        "username": "alice",
                        "site_name": "Instagram",
                        "url": profile_url,
                        "status": "Claimed",
                    },
                    "site": {
                        "name": "Instagram",
                        "headers": {"Internal-Only": "must-not-be-serialized"},
                    },
                }
            }
            (output_dir / "alice.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return CLIResult(
                args=args,
                returncode=0,
                stdout="",
                stderr="",
                duration_ms=1,
            )

        with (
            patch("connectors.maigret.shutil.which", return_value="/usr/bin/maigret"),
            patch("connectors.maigret.run_cli", side_effect=fake_run_cli),
        ):
            result = asyncio.run(MaigretConnector().search("alice"))

        self.assertEqual(len(result.evidence), 1)
        metadata = result.evidence[0].metadata
        self.assertEqual(metadata["site"], "instagram.com")
        self.assertEqual(metadata["site_name"], "Instagram")
        self.assertNotIn("must-not-be-serialized", json.dumps(metadata))
        self.assertFalse(_is_claimed({"status": "not found"}))

    def test_sherlock_uses_v016_csv_export_and_parses_claimed_rows(self):
        captured_args = []

        async def fake_run_cli(args, *, timeout, cwd=None):
            del timeout, cwd
            captured_args.extend(args)
            output_dir = Path(args[args.index("--folderoutput") + 1])
            (output_dir / "alice.csv").write_text(
                "username,name,url_main,url_user,exists,http_status,"
                "response_time_s\n"
                "alice,GitHub,https://github.com/,"
                "https://github.com/alice,QueryStatus.CLAIMED,200,0.1\n"
                "alice,Example,https://example.test/,"
                "https://example.test/alice,Available,404,0.1\n",
                encoding="utf-8",
            )
            return CLIResult(
                args=args,
                returncode=0,
                stdout="",
                stderr="",
                duration_ms=1,
            )

        with (
            patch(
                "connectors.sherlock.shutil.which",
                return_value="/usr/bin/sherlock",
            ),
            patch("connectors.sherlock.run_cli", side_effect=fake_run_cli),
        ):
            result = asyncio.run(SherlockConnector().search("alice"))

        self.assertIn("--csv", captured_args)
        self.assertIn("--local", captured_args)
        self.assertIn("--no-txt", captured_args)
        self.assertNotIn("--json", captured_args)
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.evidence[0].value, "https://github.com/alice")
        self.assertEqual(result.evidence[0].metadata["site"], "GitHub")
        self.assertEqual(result.evidence[0].metadata["platform"], "github.com")


if __name__ == "__main__":
    unittest.main()
