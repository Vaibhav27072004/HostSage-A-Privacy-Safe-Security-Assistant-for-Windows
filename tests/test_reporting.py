from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hids.logger import JsonAlertLogger
from hids.models import Alert, ScanResult
from hids.reporting import build_explained_alert, build_safe_share_report
from hids.service import HIDSService


class _UnusedCollector:
    def collect(self):  # pragma: no cover
        raise NotImplementedError


class _UnusedDetector:
    def detect(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError


def build_alert() -> Alert:
    return Alert(
        timestamp="2026-04-07T10:00:00+00:00",
        detection_reason="suspicious_port",
        risk_score=82,
        risk_label="HIGH",
        pid=4242,
        process_name="python.exe",
        process_path="C:\\Users\\Alice\\Downloads\\python.exe",
        process_command_line="C:\\Users\\Alice\\Downloads\\python.exe --token abc123",
        protocol="TCP",
        local_ip="192.168.1.5",
        local_port=55000,
        remote_ip="185.234.217.12",
        remote_port=4444,
        connection_state="ESTABLISHED",
        intel_provider="disabled",
        intel_summary="Threat intelligence disabled.",
        metadata={"matched_port": 4444},
    )


class SafeShareReportTests(unittest.TestCase):
    def test_explained_alert_includes_guidance_and_optional_redaction(self) -> None:
        explained = build_explained_alert(build_alert(), redact_sensitive=True)

        self.assertEqual(explained["explanation_title"], "Connection used a high-risk port")
        self.assertIn("Ports such as 4444 or 5555", explained["why_flagged"])
        self.assertTrue(explained["recommended_next_steps"])
        self.assertIn("local-host-1:55000", explained["redacted_local_endpoint"])
        self.assertIn("remote-host-1:4444", explained["redacted_remote_endpoint"])
        self.assertNotIn("Alice", explained["redacted_process_path"])
        self.assertNotIn("abc123", explained["redacted_command_line"])

    def test_report_redacts_sensitive_fields_and_explains_alerts(self) -> None:
        alert = build_alert()
        result = ScanResult(
            timestamp="2026-04-07T10:00:00+00:00",
            connection_count=12,
            public_remote_ip_count=3,
            alerts=[alert],
            collector_source="psutil",
            scan_duration_ms=118,
        )

        report = build_safe_share_report(
            result,
            {
                "status": "ok",
                "timestamp": result.timestamp,
                "collector_source": result.collector_source,
                "alert_count": 1,
                "warning_count": 0,
                "connection_count": result.connection_count,
                "public_remote_ip_count": result.public_remote_ip_count,
                "scan_duration_ms": result.scan_duration_ms,
                "storage": {"backend": "sqlite", "scan_count": 1, "alert_count": 1},
            },
            [alert.to_dict()],
            [result.to_dict()],
            [],
        )

        self.assertIn("HostSage Safe Share Report", report)
        self.assertIn("Connection used a high-risk port", report)
        self.assertIn("remote-host-1:4444", report)
        self.assertIn("local-host-1:55000", report)
        self.assertNotIn("185.234.217.12", report)
        self.assertNotIn("192.168.1.5", report)
        self.assertNotIn("abc123", report)
        self.assertNotIn("C:\\Users\\Alice", report)

    def test_service_writes_safe_share_report_to_disk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = JsonAlertLogger(
                export_target=None,
                scan_log_target=None,
                database_path=Path(temp_dir, "history.db").as_posix(),
            )
            logger.write_scan(
                ScanResult(
                    timestamp="2026-04-07T10:00:00+00:00",
                    connection_count=12,
                    public_remote_ip_count=3,
                    alerts=[build_alert()],
                    collector_source="psutil",
                    scan_duration_ms=118,
                )
            )
            service = HIDSService(
                collector=_UnusedCollector(),
                detector=_UnusedDetector(),
                export_logger=logger,
                history_limit=20,
            )

            report_path = Path(temp_dir, "safe_report.md")
            written_path = service.write_safe_share_report(report_path)

            self.assertEqual(written_path, report_path)
            self.assertTrue(report_path.exists())
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("Safe Share Report", content)
            self.assertIn("remote-host-1:4444", content)
            self.assertNotIn("185.234.217.12", content)

    def test_service_returns_explained_alert_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = JsonAlertLogger(
                export_target=None,
                scan_log_target=None,
                database_path=Path(temp_dir, "history.db").as_posix(),
            )
            logger.write_scan(
                ScanResult(
                    timestamp="2026-04-07T10:00:00+00:00",
                    connection_count=12,
                    public_remote_ip_count=3,
                    alerts=[build_alert()],
                    collector_source="psutil",
                    scan_duration_ms=118,
                )
            )
            service = HIDSService(
                collector=_UnusedCollector(),
                detector=_UnusedDetector(),
                export_logger=logger,
                history_limit=20,
            )

            explained_history = service.get_explained_alert_history(limit=5, redact_sensitive=True)

            self.assertEqual(len(explained_history), 1)
            self.assertIn("why_flagged", explained_history[0])
            self.assertIn("recommended_next_steps", explained_history[0])
            self.assertEqual(explained_history[0]["redacted_remote_endpoint"], "remote-host-1:4444")


if __name__ == "__main__":
    unittest.main()
