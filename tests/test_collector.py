from __future__ import annotations

import unittest
from unittest import mock

from hids.collector import ConnectionCollector
from hids.models import ProcessInfo


class ProcessCacheTests(unittest.TestCase):
    """PID reuse must not let a cached name outlive the scan that observed it."""

    def test_lookups_are_deduplicated_within_one_scan(self) -> None:
        collector = ConnectionCollector()
        with mock.patch.object(
            ConnectionCollector,
            "_resolve_process",
            wraps=collector._resolve_process,
        ):
            with mock.patch("hids.collector.psutil", None):
                first = collector._resolve_process(4242)
                second = collector._resolve_process(4242)
        self.assertIs(first, second)
        self.assertEqual(len(collector._process_cache), 1)

    def test_cache_is_cleared_at_the_start_of_each_scan(self) -> None:
        collector = ConnectionCollector()
        collector._process_cache[4242] = ProcessInfo(
            pid=4242,
            name="stale.exe",
            executable="C:\\old\\stale.exe",
            command_line="stale.exe",
        )

        with mock.patch.object(ConnectionCollector, "_collect_with_psutil", return_value=[]):
            collector.collect()

        self.assertEqual(collector._process_cache, {})

    def test_unknown_pid_resolves_without_psutil(self) -> None:
        collector = ConnectionCollector()
        with mock.patch("hids.collector.psutil", None):
            info = collector._resolve_process(-1)
        self.assertEqual(info.name, "Unknown")
        self.assertEqual(info.executable, "")


class CollectorFallbackTests(unittest.TestCase):
    def test_psutil_failure_falls_back_to_netstat(self) -> None:
        collector = ConnectionCollector()
        with mock.patch.object(
            ConnectionCollector, "_collect_with_psutil", side_effect=OSError("access denied")
        ), mock.patch.object(ConnectionCollector, "_collect_with_netstat", return_value=[]):
            result = collector.collect()

        self.assertEqual(result.source, "netstat")
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("psutil collection failed", result.warnings[0])

    def test_both_collectors_failing_raises_with_context(self) -> None:
        collector = ConnectionCollector()
        with mock.patch.object(
            ConnectionCollector, "_collect_with_psutil", side_effect=OSError("access denied")
        ), mock.patch.object(
            ConnectionCollector, "_collect_with_netstat", side_effect=OSError("netstat missing")
        ):
            with self.assertRaises(RuntimeError) as caught:
                collector.collect()

        message = str(caught.exception)
        self.assertIn("netstat missing", message)
        self.assertIn("access denied", message)


if __name__ == "__main__":
    unittest.main()
