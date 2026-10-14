from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from hids.models import ScanResult
from hids.storage import SQLiteHistoryStore, is_corruption_error


def build_scan(timestamp: str) -> ScanResult:
    return ScanResult(
        timestamp=timestamp,
        connection_count=1,
        public_remote_ip_count=0,
        alerts=[],
        collector_source="test",
        scan_duration_ms=1,
    )


def scan_timestamps(database_path: Path) -> list[str]:
    with closing(sqlite3.connect(database_path)) as connection:
        return [row[0] for row in connection.execute("SELECT timestamp FROM scans ORDER BY id")]


def corrupt(path: Path) -> None:
    with path.open("r+b") as handle:
        handle.seek(0)
        handle.write(b"\x00" * 100)


class CorruptionClassificationTests(unittest.TestCase):
    def test_corruption_messages_are_recognised(self) -> None:
        self.assertTrue(is_corruption_error(sqlite3.DatabaseError("file is not a database")))
        self.assertTrue(is_corruption_error(sqlite3.DatabaseError("database disk image is malformed")))

    def test_transient_messages_are_not_corruption(self) -> None:
        self.assertFalse(is_corruption_error(sqlite3.OperationalError("database is locked")))
        self.assertFalse(is_corruption_error(sqlite3.OperationalError("disk I/O error")))


class LockedDatabaseTests(unittest.TestCase):
    """A lock is transient. It must not delete history or silently fork it."""

    def test_locked_database_is_preserved_and_not_forked(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "history.db"
            fallback_path = Path(temp_dir) / "history_fallback.db"

            store = SQLiteHistoryStore(str(database_path), lock_timeout_seconds=0.1)
            store.write_scan(build_scan("first"))

            holder = sqlite3.connect(database_path, timeout=0.1)
            holder.execute("BEGIN EXCLUSIVE")
            holder.execute("INSERT INTO scans VALUES (NULL,'held',1,0,'test',1,'[]',0)")
            try:
                with self.assertRaises(sqlite3.DatabaseError):
                    store.write_scan(build_scan("blocked"))
            finally:
                holder.rollback()
                holder.close()

            self.assertTrue(database_path.exists())
            self.assertFalse(fallback_path.exists(), "a lock must not fork history into a fallback file")
            self.assertEqual(scan_timestamps(database_path), ["first"])

    def test_writes_resume_after_the_lock_clears(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "history.db"
            store = SQLiteHistoryStore(str(database_path), lock_timeout_seconds=0.1)
            store.write_scan(build_scan("first"))

            holder = sqlite3.connect(database_path, timeout=0.1)
            holder.execute("BEGIN EXCLUSIVE")
            holder.execute("INSERT INTO scans VALUES (NULL,'held',1,0,'test',1,'[]',0)")
            with self.assertRaises(sqlite3.DatabaseError):
                store.write_scan(build_scan("blocked"))
            holder.rollback()
            holder.close()

            store.write_scan(build_scan("after"))
            self.assertEqual(scan_timestamps(database_path), ["first", "after"])


class CorruptDatabaseTests(unittest.TestCase):
    """Corruption recovers in place, and the unreadable file is kept."""

    def test_corrupt_database_recovers_on_the_configured_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "history.db"
            fallback_path = Path(temp_dir) / "history_fallback.db"
            store = SQLiteHistoryStore(str(database_path))
            store.write_scan(build_scan("first"))
            corrupt(database_path)

            reopened = SQLiteHistoryStore(str(database_path))
            written_to = reopened.write_scan(build_scan("after"))

            self.assertEqual(str(written_to), str(database_path))
            self.assertFalse(fallback_path.exists())
            self.assertEqual(scan_timestamps(database_path), ["after"])

            stats = reopened.get_storage_stats()
            self.assertFalse(stats["fallback_active"])
            self.assertEqual(stats["database_path"], str(database_path))

    def test_corrupt_database_is_quarantined_not_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "history.db"
            store = SQLiteHistoryStore(str(database_path))
            store.write_scan(build_scan("first"))
            corrupt(database_path)

            reopened = SQLiteHistoryStore(str(database_path))
            reopened.write_scan(build_scan("after"))

            quarantined = reopened.get_storage_stats()["quarantined_paths"]
            self.assertEqual(len(quarantined), 1)
            quarantine_path = Path(quarantined[0])
            self.assertTrue(quarantine_path.exists(), "the unreadable history must be kept for review")
            self.assertIn(".corrupt-", quarantine_path.name)

    def test_connection_failure_does_not_leak_a_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "history.db"
            store = SQLiteHistoryStore(str(database_path))
            store.write_scan(build_scan("first"))
            corrupt(database_path)

            with self.assertRaises(sqlite3.DatabaseError):
                store._connect(database_path)

            # A leaked handle would keep the file locked on Windows and block
            # the cleanup that corruption recovery relies on.
            database_path.unlink()
            self.assertFalse(database_path.exists())


class StorageStatsContractTests(unittest.TestCase):
    def test_disabled_backend_exposes_the_same_keys(self) -> None:
        stats = SQLiteHistoryStore(None).get_storage_stats()
        self.assertEqual(stats["backend"], "disabled")
        self.assertFalse(stats["fallback_active"])
        self.assertIsNone(stats["configured_database_path"])

    def test_healthy_database_is_not_marked_as_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "history.db"
            store = SQLiteHistoryStore(str(database_path))
            store.write_scan(build_scan("first"))
            stats = store.get_storage_stats()
            self.assertFalse(stats["fallback_active"])
            self.assertEqual(stats["database_path"], str(database_path))
            self.assertEqual(stats["scan_count"], 1)


if __name__ == "__main__":
    unittest.main()
