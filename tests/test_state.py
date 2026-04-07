from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from hids.models import ConnectionRecord
from hids.state import DetectionState


def build_connection() -> ConnectionRecord:
    return ConnectionRecord(
        timestamp="2026-04-06T00:00:00+00:00",
        protocol="TCP",
        family="IPv4",
        local_ip="192.168.1.10",
        local_port=55000,
        remote_ip="8.8.8.8",
        remote_port=443,
        state="ESTABLISHED",
        pid=1234,
        process_name="python.exe",
        process_path="C:\\Python\\python.exe",
        process_command_line="python app.py",
        direction="OUTBOUND",
    )


class DetectionStateTests(unittest.TestCase):
    def test_state_persists_beacon_history(self) -> None:
        connection = build_connection()
        state = DetectionState(max_history=5)
        state.record_scan([connection], datetime(2026, 4, 6, tzinfo=timezone.utc))

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"
            state.save(path)
            loaded = DetectionState.load(path, max_history=5)

            self.assertEqual(loaded.get_beacon_history(connection), state.get_beacon_history(connection))


if __name__ == "__main__":
    unittest.main()
