from __future__ import annotations

import unittest
from datetime import datetime, timezone

from hids.config import RuleConfig, ThreatIntelConfig
from hids.detector import Detector
from hids.intel import ThreatIntelClient
from hids.models import ConnectionRecord
from hids.state import DetectionState

TRUSTED_IP = "185.234.217.12"
UNTRUSTED_IP = "45.33.32.156"


def build_connection(
    *,
    remote_ip: str,
    remote_port: int = 443,
    local_port: int = 55000,
    process_name: str = "python.exe",
    process_path: str = "C:\\Python\\python.exe",
    command_line: str = "python app.py",
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
        pid=100,
        process_name=process_name,
        process_path=process_path,
        process_command_line=command_line,
        direction="OUTBOUND",
    )


class AllowlistScopeTests(unittest.TestCase):
    """known_networks must suppress every rule, not only threat-intel rules."""

    def setUp(self) -> None:
        self.rules = RuleConfig(
            suspicious_ports={4444},
            suspicious_process_names={"nc.exe"},
            suspicious_command_line_patterns={" -enc "},
            known_networks=[f"{TRUSTED_IP}/32"],
            outbound_connection_threshold=3,
            unique_ip_threshold=3,
            beacon_min_samples=4,
            beacon_jitter_seconds=0.5,
        )
        self.detector = Detector(self.rules, ThreatIntelClient(ThreatIntelConfig()))

    def _reasons(self, connections: list[ConnectionRecord]) -> list[str]:
        alerts = self.detector.detect(
            connections,
            DetectionState(),
            datetime(2026, 4, 6, tzinfo=timezone.utc),
        )
        return [alert.detection_reason for alert in alerts]

    def test_trusted_ip_suppresses_suspicious_port(self) -> None:
        self.assertNotIn(
            "suspicious_port",
            self._reasons([build_connection(remote_ip=TRUSTED_IP, remote_port=4444)]),
        )

    def test_untrusted_ip_still_reports_suspicious_port(self) -> None:
        self.assertIn(
            "suspicious_port",
            self._reasons([build_connection(remote_ip=UNTRUSTED_IP, remote_port=4444)]),
        )

    def test_trusted_ip_suppresses_suspicious_process_and_command_line(self) -> None:
        connection = build_connection(
            remote_ip=TRUSTED_IP,
            process_name="nc.exe",
            process_path="C:\\tools\\nc.exe",
            command_line="nc.exe -enc payload",
        )
        reasons = self._reasons([connection])
        self.assertNotIn("suspicious_process", reasons)
        self.assertNotIn("suspicious_command_line", reasons)

    def test_trusted_ip_suppresses_outbound_volume(self) -> None:
        connections = [
            build_connection(remote_ip=TRUSTED_IP, local_port=55000 + offset) for offset in range(5)
        ]
        self.assertNotIn("high_frequency_outbound", self._reasons(connections))

    def test_cidr_range_is_honoured(self) -> None:
        rules = RuleConfig(
            suspicious_ports={4444},
            known_networks=["45.33.32.0/24"],
            outbound_connection_threshold=50,
            unique_ip_threshold=50,
        )
        detector = Detector(rules, ThreatIntelClient(ThreatIntelConfig()))
        alerts = detector.detect(
            [build_connection(remote_ip=UNTRUSTED_IP, remote_port=4444)],
            DetectionState(),
            datetime(2026, 4, 6, tzinfo=timezone.utc),
        )
        self.assertEqual(alerts, [])

    def test_mixed_traffic_only_reports_the_untrusted_host(self) -> None:
        connections = [
            build_connection(remote_ip=TRUSTED_IP, remote_port=4444, local_port=55001),
            build_connection(remote_ip=UNTRUSTED_IP, remote_port=4444, local_port=55002),
        ]
        alerts = self.detector.detect(
            connections,
            DetectionState(),
            datetime(2026, 4, 6, tzinfo=timezone.utc),
        )
        flagged = {alert.remote_ip for alert in alerts}
        self.assertEqual(flagged, {UNTRUSTED_IP})


if __name__ == "__main__":
    unittest.main()
