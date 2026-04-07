from __future__ import annotations

import unittest
from datetime import datetime, timezone

from hids.config import RuleConfig, ThreatIntelConfig
from hids.detector import Detector
from hids.intel import ThreatIntelClient
from hids.models import ConnectionRecord
from hids.state import DetectionState


def build_connection(
    *,
    remote_ip: str,
    remote_port: int,
    pid: int = 100,
    process_name: str = "python.exe",
    process_path: str = "C:\\Python\\python.exe",
    command_line: str = "python app.py",
    local_port: int = 55000,
) -> ConnectionRecord:
    return ConnectionRecord(
        timestamp="2026-04-06T00:00:00+00:00",
        protocol="TCP",
        family="IPv4",
        local_ip="192.168.1.10",
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state="ESTABLISHED",
        pid=pid,
        process_name=process_name,
        process_path=process_path,
        process_command_line=command_line,
        direction="OUTBOUND",
    )


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        rules = RuleConfig(
            suspicious_ports={4444},
            suspicious_process_names={"powershell.exe"},
            suspicious_command_line_patterns={" -enc "},
            known_networks=[],
            outbound_connection_threshold=3,
            unique_ip_threshold=3,
            beacon_min_samples=4,
            beacon_jitter_seconds=0.5,
            medium_intel_threshold=40,
            high_intel_threshold=75,
        )
        intel_client = ThreatIntelClient(ThreatIntelConfig())
        self.detector = Detector(rules, intel_client)
        self.state = DetectionState()

    def test_suspicious_port_rule_generates_alert(self) -> None:
        connection = build_connection(remote_ip="185.234.217.12", remote_port=4444)
        alerts = self.detector.detect([connection], self.state, datetime(2026, 4, 6, tzinfo=timezone.utc))
        self.assertTrue(any(alert.detection_reason == "suspicious_port" for alert in alerts))

    def test_suspicious_command_line_rule_generates_alert(self) -> None:
        connection = build_connection(
            remote_ip="185.234.217.12",
            remote_port=443,
            process_name="powershell.exe",
            command_line="powershell.exe -enc aQBlAHgA",
        )
        alerts = self.detector.detect([connection], self.state, datetime(2026, 4, 6, tzinfo=timezone.utc))
        self.assertTrue(any(alert.detection_reason == "suspicious_command_line" for alert in alerts))

    def test_unique_ip_rule_generates_alert(self) -> None:
        connections = [
            build_connection(remote_ip="8.8.8.8", remote_port=443, local_port=55001),
            build_connection(remote_ip="1.1.1.1", remote_port=443, local_port=55002),
            build_connection(remote_ip="9.9.9.9", remote_port=443, local_port=55003),
        ]
        alerts = self.detector.detect(connections, self.state, datetime(2026, 4, 6, tzinfo=timezone.utc))
        self.assertTrue(any(alert.detection_reason == "process_many_unique_ips" for alert in alerts))

    def test_high_frequency_outbound_rule_generates_alert(self) -> None:
        connections = [
            build_connection(remote_ip="8.8.8.8", remote_port=443, local_port=55001),
            build_connection(remote_ip="8.8.4.4", remote_port=443, local_port=55002),
            build_connection(remote_ip="1.1.1.1", remote_port=443, local_port=55003),
        ]
        alerts = self.detector.detect(connections, self.state, datetime(2026, 4, 6, tzinfo=timezone.utc))
        self.assertTrue(any(alert.detection_reason == "high_frequency_outbound" for alert in alerts))

    def test_periodic_beacon_rule_generates_alert(self) -> None:
        connection = build_connection(remote_ip="8.8.8.8", remote_port=443)
        for second in (0, 10, 20):
            self.detector.detect(
                [connection],
                self.state,
                datetime(2026, 4, 6, 0, 0, second, tzinfo=timezone.utc),
            )
            self.detector.detect([], self.state, datetime(2026, 4, 6, 0, 0, second + 1, tzinfo=timezone.utc))

        alerts = self.detector.detect(
            [connection],
            self.state,
            datetime(2026, 4, 6, 0, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(any(alert.detection_reason == "periodic_beacon" for alert in alerts))


if __name__ == "__main__":
    unittest.main()
