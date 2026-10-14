from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hids.api import create_app
from hids.cli import LOOPBACK_HOSTS, warn_if_api_exposed
from hids.logger import JsonAlertLogger
from hids.models import Alert, ScanResult
from hids.service import HIDSService
from hids.state import DetectionState


class _StubCollector:
    def collect(self):  # pragma: no cover - the API tests never scan
        raise AssertionError("the API tests must not trigger a scan")


class _StubDetector:
    def detect(self, connections, state, observed_at=None):  # pragma: no cover
        raise AssertionError("the API tests must not trigger detection")


def build_alert() -> Alert:
    return Alert(
        timestamp="2026-04-06T00:00:00+00:00",
        detection_reason="suspicious_port",
        risk_score=82,
        risk_label="HIGH",
        pid=4242,
        process_name="python.exe",
        process_path="C:\\Users\\alice\\python.exe",
        process_command_line="python.exe secret_tool.py --token abcdef",
        protocol="TCP",
        local_ip="192.168.1.10",
        local_port=55000,
        remote_ip="45.33.32.156",
        remote_port=4444,
        connection_state="ESTABLISHED",
        intel_provider="disabled",
        intel_summary="Threat intelligence disabled.",
        metadata={"matched_port": 4444},
    )


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        base = Path(self._temp_dir.name)
        logger = JsonAlertLogger(None, str(base / "scans.jsonl"), str(base / "history.db"))
        self.service = HIDSService(
            collector=_StubCollector(),
            detector=_StubDetector(),
            export_logger=logger,
            detection_state=DetectionState(),
        )
        result = ScanResult(
            timestamp="2026-04-06T00:00:00+00:00",
            connection_count=12,
            public_remote_ip_count=3,
            alerts=[build_alert()],
            collector_source="psutil",
            scan_duration_ms=42,
        )
        self.service._latest_result = result
        self.service._history.append(result)

        app = create_app(self.service)
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def test_every_documented_endpoint_responds(self) -> None:
        endpoints = [
            "/health",
            "/summary",
            "/alerts",
            "/explained-alerts",
            "/history",
            "/alert-history",
            "/explained-alert-history",
            "/alert-groups",
            "/safe-share-report",
        ]
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 200)
                self.assertIsNotNone(response.get_json())

    def test_summary_reports_the_latest_scan(self) -> None:
        payload = self.client.get("/summary").get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["risk_breakdown"], {"HIGH": 1})
        self.assertEqual(payload["history_count"], 1)

    def test_explained_alerts_add_guidance(self) -> None:
        payload = self.client.get("/explained-alerts").get_json()
        self.assertEqual(len(payload), 1)
        self.assertIn("why_flagged", payload[0])
        self.assertIn("recommended_next_steps", payload[0])

    def test_redact_flag_replaces_sensitive_fields(self) -> None:
        plain = self.client.get("/explained-alerts").get_json()[0]
        redacted = self.client.get("/explained-alerts?redact=1").get_json()[0]

        self.assertNotIn("redacted_command_line", plain)
        self.assertIn("<redacted-path>", redacted["redacted_process_path"])
        self.assertNotIn("--token abcdef", redacted["redacted_command_line"])
        self.assertTrue(redacted["redacted_remote_endpoint"].startswith("remote-host-"))

    def test_limit_parameter_is_honoured_and_junk_is_ignored(self) -> None:
        self.assertEqual(len(self.client.get("/alerts?limit=0").get_json()), 0)
        self.assertEqual(len(self.client.get("/alerts?limit=notanumber").get_json()), 1)

    def test_safe_share_report_is_redacted_markdown(self) -> None:
        report = self.client.get("/safe-share-report").get_json()["report_markdown"]
        self.assertIn("# HostSage Safe Share Report", report)
        self.assertNotIn("45.33.32.156", report)
        self.assertNotIn("--token abcdef", report)
        self.assertNotIn("C:\\Users\\alice", report)


class ApiExposureWarningTests(unittest.TestCase):
    def test_loopback_hosts_are_silent(self) -> None:
        for host in sorted(LOOPBACK_HOSTS):
            with self.subTest(host=host):
                self.assertIsNone(warn_if_api_exposed(host))


if __name__ == "__main__":
    unittest.main()
