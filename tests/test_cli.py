from __future__ import annotations

import unittest
from pathlib import Path

from hids.cli import build_argument_parser
from hids.config import HIDSConfig
from hids.models import Alert, LogWriteResult, ScanResult
from hids.terminal_ui import build_config_overview_lines, build_scan_report_lines


def build_alert() -> Alert:
    return Alert(
        timestamp="2026-04-07T10:00:00+00:00",
        detection_reason="suspicious_port",
        risk_score=82,
        risk_label="HIGH",
        pid=4242,
        process_name="python.exe",
        process_path="C:\\Python\\python.exe",
        process_command_line="python app.py",
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


class CliParsingTests(unittest.TestCase):
    def test_parser_accepts_terminal_flags(self) -> None:
        args = build_argument_parser().parse_args(["--terminal", "--no-color"])
        self.assertTrue(args.terminal)
        self.assertTrue(args.no_color)

    def test_parser_accepts_share_report_flag_with_optional_path(self) -> None:
        args = build_argument_parser().parse_args(["--share-report", "logs\\safe.md"])
        self.assertEqual(args.share_report, "logs\\safe.md")


class CliRenderingTests(unittest.TestCase):
    def test_scan_report_lines_include_alerts_and_saved_paths(self) -> None:
        result = ScanResult(
            timestamp="2026-04-07T10:00:00+00:00",
            connection_count=12,
            public_remote_ip_count=3,
            alerts=[build_alert()],
            collector_source="psutil",
            scan_duration_ms=118,
        )
        log_result = LogWriteResult(
            alert_path=Path("logs/alerts.jsonl"),
            scan_path=Path("logs/scans.jsonl"),
            database_path=Path("logs/hids_history.db"),
        )

        rendered = "\n".join(build_scan_report_lines(result, log_result, color_enabled=False))

        self.assertIn("HostSage Scan Summary", rendered)
        self.assertIn("suspicious port", rendered)
        self.assertIn("why:", rendered)
        self.assertIn("next:", rendered)
        self.assertIn("python.exe", rendered)
        self.assertIn("alerts.jsonl", rendered)
        self.assertIn("hids_history.db", rendered)

    def test_config_overview_lines_report_storage_and_intel_status(self) -> None:
        config = HIDSConfig()
        config.threat_intel.abuseipdb_api_key = "token"
        config.rules.known_network_files = ["known_ips.example.txt"]

        rendered = "\n".join(
            build_config_overview_lines(
                config,
                "config.example.json",
                {
                    "backend": "sqlite",
                    "database_path": "logs/hids_history.db",
                    "scan_count": 5,
                    "alert_count": 2,
                },
                color_enabled=False,
            )
        )

        self.assertIn("Configuration and Storage", rendered)
        self.assertIn("Enabled", rendered)
        self.assertIn("logs/hids_history.db", rendered)
        self.assertIn("Trusted files", rendered)


if __name__ == "__main__":
    unittest.main()
