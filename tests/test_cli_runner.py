# ruff: noqa: E402

import asyncio
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from connectors.cli import CLIOutputLimitExceeded, run_cli


class CLIRunnerTests(unittest.TestCase):
    def test_executes_argument_array_without_a_shell(self):
        result = asyncio.run(
            run_cli(
                [
                    sys.executable,
                    "-c",
                    "import sys; print(sys.argv[1])",
                    "$(printf unsafe)",
                ],
                timeout=5,
                max_output_bytes=1024,
            )
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "$(printf unsafe)")

    def test_kills_process_when_output_limit_is_exceeded(self):
        with self.assertRaises(CLIOutputLimitExceeded):
            asyncio.run(
                run_cli(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.write('x' * 4096)",
                    ],
                    timeout=5,
                    max_output_bytes=128,
                )
            )


if __name__ == "__main__":
    unittest.main()
