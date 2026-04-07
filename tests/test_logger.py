from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hids.logger import JsonAlertLogger
from hids.models import Alert, ScanResult


class LoggerTests(unittest.TestCase):
    @staticmethod
    def _build_alert(
        *,
        timestamp: str = "2026-04-06T00:00:00+00:00",
        reason: str = "suspicious_port",
        risk_score: int = 80,
        risk_label: str = "HIGH",
        process_name: str = "python.exe",
        remote_ip: str = "185.234.217.12",
        remote_port: int = 4444,
        metadata: dict[str, object] | None = None,
    ) -> Alert:
        return Alert(
            timestamp=timestamp,
            detection_reason=reason,
            risk_score=risk_score,
            risk_label=risk_label,
            pid=1234,
            process_name=process_name,
            process_path="C:\\Python\\python.exe",
            process_command_line="python app.py",
            protocol="TCP",
            local_ip="192.168.1.10",
            local_port=55000,
            remote_ip=remote_ip,
            remote_port=remote_port,
            connection_state="ESTABLISHED",
            intel_provider="disabled",
            intel_summary="Threat intelligence disabled.",
            metadata=metadata or {"matched_port": remote_port},
        )

    def test_logger_writes_jsonl_alerts(self) -> None:
        alert = self._build_alert()
        result = ScanResult(
            timestamp="2026-04-06T00:00:00+00:00",
            connection_count=1,
            public_remote_ip_count=1,
            alerts=[alert],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            logger = JsonAlertLogger(temp_dir)
            path = logger.write_scan(result)

            self.assertIsNotNone(path)
            self.assertIsNotNone(path.alert_path)
            lines = Path(path.alert_path).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            payload = json.loads(lines[0])
            self.assertEqual(payload["process_name"], "python.exe")

    def test_logger_writes_and_reads_scan_history(self) -> None:
        result = ScanResult(
            timestamp="2026-04-06T00:00:00+00:00",
            connection_count=10,
            public_remote_ip_count=4,
            alerts=[],
            collector_source="psutil",
            scan_duration_ms=25,
            warnings=["psutil collection failed once"],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            logger = JsonAlertLogger(export_target=None, scan_log_target=Path(temp_dir, "scans.jsonl").as_posix())
            write_result = logger.write_scan(result)

            self.assertIsNotNone(write_result)
            self.assertIsNotNone(write_result.scan_path)
            recent = logger.load_recent_scans(limit=5)
            self.assertEqual(len(recent), 1)
            self.assertEqual(recent[0].collector_source, "psutil")

    def test_logger_persists_sqlite_history_and_alert_groups(self) -> None:
        first_result = ScanResult(
            timestamp="2026-04-06T00:00:00+00:00",
            connection_count=3,
            public_remote_ip_count=1,
            alerts=[self._build_alert()],
            collector_source="psutil",
            scan_duration_ms=20,
        )
        second_result = ScanResult(
            timestamp="2026-04-06T00:05:00+00:00",
            connection_count=4,
            public_remote_ip_count=2,
            alerts=[
                self._build_alert(timestamp="2026-04-06T00:05:00+00:00"),
                self._build_alert(
                    timestamp="2026-04-06T00:05:00+00:00",
                    reason="suspicious_command_line",
                    risk_score=82,
                    process_name="powershell.exe",
                    remote_ip="104.16.0.1",
                    remote_port=443,
                    metadata={"matched_pattern": " -enc "},
                ),
            ],
            collector_source="netstat",
            scan_duration_ms=40,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir, "hids_history.db")
            logger = JsonAlertLogger(
                export_target=None,
                scan_log_target=None,
                database_path=database_path.as_posix(),
            )

            first_write = logger.write_scan(first_result)
            second_write = logger.write_scan(second_result)

            self.assertIsNotNone(first_write)
            self.assertIsNotNone(second_write)
            self.assertIsNotNone(second_write.database_path)

            recent_scans = logger.load_recent_scans(limit=10)
            self.assertEqual(len(recent_scans), 2)
            self.assertEqual(recent_scans[-1].collector_source, "netstat")

            alert_history = logger.load_recent_alerts(limit=10)
            self.assertEqual(len(alert_history), 3)
            self.assertEqual(alert_history[0]["scan_timestamp"], "2026-04-06T00:05:00+00:00")

            grouped_alerts = logger.load_alert_groups(limit=10)
            self.assertEqual(len(grouped_alerts), 2)
            self.assertEqual(grouped_alerts[0]["occurrence_count"], 2)
            self.assertEqual(grouped_alerts[0]["detection_reason"], "suspicious_port")

            stats = logger.get_storage_stats()
            self.assertEqual(stats["backend"], "sqlite")
            self.assertEqual(stats["scan_count"], 2)
            self.assertEqual(stats["alert_count"], 3)


if __name__ == "__main__":
    unittest.main()
