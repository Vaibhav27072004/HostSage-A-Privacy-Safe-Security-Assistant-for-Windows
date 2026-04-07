from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hids.logger import JsonAlertLogger
from hids.models import Alert, ScanResult
from hids.service import HIDSService


class _UnusedCollector:
    def collect(self):  # pragma: no cover
        raise NotImplementedError


class _UnusedDetector:
    def detect(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError


def build_alert(timestamp: str, *, reason: str = "suspicious_port", risk_label: str = "HIGH") -> Alert:
    return Alert(
        timestamp=timestamp,
        detection_reason=reason,
        risk_score=80 if risk_label == "HIGH" else 55,
        risk_label=risk_label,
        pid=1234,
        process_name="python.exe",
        process_path="C:\\Python\\python.exe",
        process_command_line="python app.py",
        protocol="TCP",
        local_ip="192.168.1.10",
        local_port=55000,
        remote_ip="185.234.217.12",
        remote_port=4444,
        connection_state="ESTABLISHED",
        intel_provider="disabled",
        intel_summary="Threat intelligence disabled.",
        metadata={"matched_port": 4444},
    )


class ServiceHistoryTests(unittest.TestCase):
    def test_service_reads_persisted_alert_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = JsonAlertLogger(
                export_target=None,
                scan_log_target=None,
                database_path=Path(temp_dir, "history.db").as_posix(),
            )
            logger.write_scan(
                ScanResult(
                    timestamp="2026-04-06T00:00:00+00:00",
                    connection_count=3,
                    public_remote_ip_count=1,
                    alerts=[build_alert("2026-04-06T00:00:00+00:00")],
                    collector_source="psutil",
                    scan_duration_ms=10,
                )
            )
            logger.write_scan(
                ScanResult(
                    timestamp="2026-04-06T01:00:00+00:00",
                    connection_count=4,
                    public_remote_ip_count=2,
                    alerts=[build_alert("2026-04-06T01:00:00+00:00", reason="suspicious_command_line")],
                    collector_source="psutil",
                    scan_duration_ms=20,
                )
            )

            service = HIDSService(
                collector=_UnusedCollector(),
                detector=_UnusedDetector(),
                export_logger=logger,
                history_limit=20,
            )

            history = service.get_alert_history(limit=10)
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["detection_reason"], "suspicious_command_line")

            grouped = service.get_alert_groups(limit=10)
            self.assertEqual(len(grouped), 2)

            summary = service.get_summary()
            self.assertEqual(summary["storage"]["scan_count"], 2)
            self.assertEqual(summary["storage"]["alert_count"], 2)


if __name__ == "__main__":
    unittest.main()
