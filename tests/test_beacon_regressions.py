from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hids.config import RuleConfig, ThreatIntelConfig
from hids.detector import Detector
from hids.intel import ThreatIntelClient
from hids.models import ConnectionRecord
from hids.state import DetectionState


def build_connection(
    *,
    remote_ip: str = "185.234.217.12",
    remote_port: int = 443,
    local_port: int = 55000,
    pid: int = 4242,
    process_name: str = "browser.exe",
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
        process_path="C:\\Program Files\\browser.exe",
        process_command_line="browser.exe",
        direction="OUTBOUND",
    )


def build_detector(**overrides: object) -> Detector:
    settings: dict[str, object] = {
        "suspicious_ports": {4444},
        "suspicious_process_names": {"nc.exe"},
        "suspicious_command_line_patterns": {" -enc "},
        "known_networks": [],
        "outbound_connection_threshold": 50,
        "unique_ip_threshold": 50,
        "beacon_min_samples": 4,
        "beacon_jitter_seconds": 3.0,
        "beacon_min_interval_seconds": 1.0,
    }
    settings.update(overrides)
    return Detector(RuleConfig(**settings), ThreatIntelClient(ThreatIntelConfig()))


class ConcurrentSocketBeaconTests(unittest.TestCase):
    """A process holding several sockets open to one endpoint is not a beacon."""

    def test_single_scan_with_many_sockets_does_not_beacon(self) -> None:
        connections = [build_connection(local_port=55000 + offset) for offset in range(20)]
        alerts = build_detector().detect(
            connections,
            DetectionState(),
            datetime(2026, 4, 6, tzinfo=timezone.utc),
        )
        self.assertEqual([alert.detection_reason for alert in alerts], [])

    def test_concurrent_sockets_record_one_sample_per_scan(self) -> None:
        state = DetectionState()
        connections = [build_connection(local_port=55000 + offset) for offset in range(8)]
        state.record_scan(connections, datetime(2026, 4, 6, tzinfo=timezone.utc))
        self.assertEqual(len(state.get_beacon_history(connections[0])), 1)

    def test_repeated_bursts_never_build_zero_intervals(self) -> None:
        state = DetectionState()
        detector = build_detector()
        base = datetime(2026, 4, 6, tzinfo=timezone.utc)

        for scan_index in range(6):
            burst = [
                build_connection(local_port=56000 + (scan_index * 100) + offset)
                for offset in range(6)
            ]
            detector.detect(burst, state, base + timedelta(seconds=scan_index * 30))

        history = state.get_beacon_history(build_connection())
        self.assertEqual(len(history), 6)
        intervals = [history[index] - history[index - 1] for index in range(1, len(history))]
        self.assertTrue(all(interval > 0 for interval in intervals), intervals)

    def test_long_lived_sockets_accrue_no_further_samples(self) -> None:
        state = DetectionState()
        detector = build_detector()
        base = datetime(2026, 4, 6, tzinfo=timezone.utc)
        connections = [build_connection(local_port=55000 + offset) for offset in range(6)]

        for scan_index in range(10):
            alerts = detector.detect(connections, state, base + timedelta(seconds=scan_index * 5))
            self.assertNotIn("periodic_beacon", [alert.detection_reason for alert in alerts])

        # The sockets never closed, so after the first observation there is
        # nothing new to sample and no beacon pattern can form.
        self.assertEqual(len(state.get_beacon_history(connections[0])), 1)

    def test_genuine_periodic_reconnection_still_alerts(self) -> None:
        state = DetectionState()
        detector = build_detector()
        base = datetime(2026, 4, 6, tzinfo=timezone.utc)
        connection = build_connection()

        for scan_index in range(4):
            detector.detect([connection], state, base + timedelta(seconds=scan_index * 30))
            # The socket closes between check-ins, so the next one counts as new.
            detector.detect([], state, base + timedelta(seconds=(scan_index * 30) + 1))

        alerts = detector.detect([connection], state, base + timedelta(seconds=120))
        self.assertIn("periodic_beacon", [alert.detection_reason for alert in alerts])

    def test_sub_interval_samples_are_rejected(self) -> None:
        detector = build_detector(beacon_min_interval_seconds=5.0)
        # Evenly spaced, but far tighter than one configured beacon interval.
        self.assertFalse(detector._looks_periodic([0.0, 0.2, 0.4, 0.6, 0.8]))
        self.assertTrue(detector._looks_periodic([0.0, 30.0, 60.0, 90.0, 120.0]))


class StatePersistenceTests(unittest.TestCase):
    """Restarts must not treat already-open sockets as fresh observations."""

    def test_previous_connections_survive_a_restart(self) -> None:
        connections = [build_connection(local_port=55000 + offset) for offset in range(4)]
        state = DetectionState(max_history=10)
        state.record_scan(connections, datetime(2026, 4, 6, tzinfo=timezone.utc))

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"
            state.save(path)
            restored = DetectionState.load(path, max_history=10)

        before = len(restored.get_beacon_history(connections[0]))
        restored.record_scan(connections, datetime(2026, 4, 6, 0, 0, 30, tzinfo=timezone.utc))
        self.assertEqual(len(restored.get_beacon_history(connections[0])), before)

    def test_restart_does_not_immediately_beacon_on_open_sockets(self) -> None:
        detector = build_detector()
        connections = [build_connection(local_port=55000 + offset) for offset in range(12)]
        state = DetectionState(max_history=20)
        base = datetime(2026, 4, 6, tzinfo=timezone.utc)
        state.record_scan(connections, base)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"
            for restart in range(1, 6):
                state.save(path)
                state = DetectionState.load(path, max_history=20)
                alerts = detector.detect(connections, state, base + timedelta(seconds=restart))
                self.assertNotIn("periodic_beacon", [alert.detection_reason for alert in alerts])

    def test_malformed_previous_connections_are_ignored(self) -> None:
        payload = {
            "max_history": 5,
            "beacon_history": [],
            "previous_connections": [["not-an-int", "TCP"], None, 7, ["x"] * 7],
        }
        state = DetectionState.from_dict(payload, max_history=5)
        self.assertEqual(state.to_dict()["previous_connections"], [])


if __name__ == "__main__":
    unittest.main()
