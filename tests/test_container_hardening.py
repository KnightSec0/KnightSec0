from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ContainerHardeningTests(unittest.TestCase):
    def test_application_images_run_as_fixed_non_root_user(self):
        for relative_path in (
            "orchestrator/Dockerfile",
            "dashboard/Dockerfile",
        ):
            dockerfile = (ROOT / relative_path).read_text(encoding="utf-8")
            with self.subTest(dockerfile=relative_path):
                self.assertIn("USER deepvault:deepvault", dockerfile)
                self.assertIn("--uid 10001", dockerfile)
                self.assertIn("--gid 10001", dockerfile)

    def test_compose_drops_capabilities_and_mounts_source_read_only(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn("- ./orchestrator:/app:ro", compose)
        self.assertIn("- ./dashboard:/app:ro", compose)
        self.assertGreaterEqual(compose.count("no-new-privileges:true"), 2)
        self.assertGreaterEqual(compose.count("cap_drop:"), 2)

    def test_celery_beat_schedule_uses_writable_data_volume(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "orchestrator/Dockerfile").read_text(
            encoding="utf-8"
        )

        schedule_option = "--schedule=/data/celerybeat-schedule"
        self.assertIn(schedule_option, compose)
        self.assertIn(schedule_option, dockerfile)


if __name__ == "__main__":
    unittest.main()
