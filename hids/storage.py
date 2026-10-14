from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from hids.models import Alert, ScanResult

# Only these errors mean the file itself is unusable. Everything else a
# DatabaseError can carry - a lock, a busy writer, a full disk - is transient,
# and deleting history to recover from it would destroy readable data.
CORRUPTION_MARKERS = (
    "file is not a database",
    "database disk image is malformed",
    "file is encrypted",
    "unsupported file format",
)

DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0


def is_corruption_error(error: BaseException) -> bool:
    message = str(error).lower()
    return any(marker in message for marker in CORRUPTION_MARKERS)


class SQLiteHistoryStore:
    def __init__(
        self,
        database_path: str | None,
        *,
        lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self._database_path = Path(database_path) if database_path else None
        self._active_database_path = self._database_path
        self._lock_timeout_seconds = lock_timeout_seconds
        self._using_fallback = False
        self._quarantined_paths: list[str] = []

    @property
    def enabled(self) -> bool:
        return self._database_path is not None

    @property
    def database_path(self) -> Path | None:
        return self._active_database_path

    def write_scan(self, result: ScanResult) -> Path | None:
        if self._database_path is None:
            return None

        last_error: sqlite3.DatabaseError | None = None
        for database_path in self._candidate_paths():
            database_path.parent.mkdir(parents=True, exist_ok=True)
            self._active_database_path = database_path
            try:
                self._write_scan_once(result, database_path)
                self._using_fallback = database_path != self._database_path
                return database_path
            except sqlite3.DatabaseError as exc:
                last_error = exc
                if not is_corruption_error(exc):
                    # A lock or other transient failure. Raising keeps history in
                    # one file and lets the caller report the failed scan write,
                    # instead of silently splitting it across a second database.
                    raise
                self._reset_database_files(database_path)
                try:
                    self._write_scan_once(result, database_path)
                    self._using_fallback = database_path != self._database_path
                    return database_path
                except sqlite3.DatabaseError as retry_exc:
                    last_error = retry_exc
                    continue

        if last_error is not None:
            raise last_error
        return None

    def _write_scan_once(self, result: ScanResult, database_path: Path) -> None:
        with closing(self._connect(database_path)) as connection:
            self._ensure_schema(connection)
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    timestamp,
                    connection_count,
                    public_remote_ip_count,
                    collector_source,
                    scan_duration_ms,
                    warnings_json,
                    alert_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.timestamp,
                    result.connection_count,
                    result.public_remote_ip_count,
                    result.collector_source,
                    result.scan_duration_ms,
                    json.dumps(result.warnings, separators=(",", ":")),
                    len(result.alerts),
                ),
            )
            scan_id = int(cursor.lastrowid)

            if result.alerts:
                connection.executemany(
                    """
                    INSERT INTO alerts (
                        scan_id,
                        timestamp,
                        detection_reason,
                        risk_score,
                        risk_label,
                        pid,
                        process_name,
                        process_path,
                        process_command_line,
                        protocol,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        connection_state,
                        intel_provider,
                        intel_summary,
                        metadata_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            scan_id,
                            alert.timestamp,
                            alert.detection_reason,
                            alert.risk_score,
                            alert.risk_label,
                            alert.pid,
                            alert.process_name,
                            alert.process_path,
                            alert.process_command_line,
                            alert.protocol,
                            alert.local_ip,
                            alert.local_port,
                            alert.remote_ip,
                            alert.remote_port,
                            alert.connection_state,
                            alert.intel_provider,
                            alert.intel_summary,
                            json.dumps(alert.metadata, separators=(",", ":")),
                        )
                        for alert in result.alerts
                    ],
                )
            connection.commit()

    def load_recent_scans(self, limit: int) -> list[ScanResult]:
        if self._database_path is None or limit < 1:
            return []

        for database_path in self._candidate_paths(existing_only=True):
            with closing(self._connect(database_path)) as connection:
                self._ensure_schema(connection)
                scan_rows = connection.execute(
                    """
                    SELECT
                        id,
                        timestamp,
                        connection_count,
                        public_remote_ip_count,
                        collector_source,
                        scan_duration_ms,
                        warnings_json
                    FROM scans
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()

                if not scan_rows:
                    continue

                self._active_database_path = database_path
                ordered_rows = list(reversed(scan_rows))
                scan_ids = [int(row["id"]) for row in ordered_rows]
                placeholders = ",".join("?" for _ in scan_ids)
                alert_rows = connection.execute(
                    f"""
                    SELECT
                        scan_id,
                        timestamp,
                        detection_reason,
                        risk_score,
                        risk_label,
                        pid,
                        process_name,
                        process_path,
                        process_command_line,
                        protocol,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        connection_state,
                        intel_provider,
                        intel_summary,
                        metadata_json
                    FROM alerts
                    WHERE scan_id IN ({placeholders})
                    ORDER BY scan_id ASC, risk_score DESC, id ASC
                    """,
                    tuple(scan_ids),
                ).fetchall()

            alerts_by_scan_id: dict[int, list[Alert]] = {scan_id: [] for scan_id in scan_ids}
            for row in alert_rows:
                alerts_by_scan_id[int(row["scan_id"])].append(self._row_to_alert(row))

            results: list[ScanResult] = []
            for row in ordered_rows:
                scan_id = int(row["id"])
                results.append(
                    ScanResult(
                        timestamp=str(row["timestamp"]),
                        connection_count=int(row["connection_count"]),
                        public_remote_ip_count=int(row["public_remote_ip_count"]),
                        alerts=alerts_by_scan_id.get(scan_id, []),
                        collector_source=str(row["collector_source"]),
                        scan_duration_ms=int(row["scan_duration_ms"]),
                        warnings=self._load_json_list(row["warnings_json"]),
                    )
                )
            return results
        return []

    def load_recent_alerts(
        self,
        limit: int,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, object]]:
        if self._database_path is None or limit < 1:
            return []

        filters = []
        params: list[object] = []
        if risk_label:
            filters.append("a.risk_label = ?")
            params.append(risk_label.upper())
        if reason:
            filters.append("a.detection_reason = ?")
            params.append(reason)

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        query = f"""
            SELECT
                a.id,
                a.scan_id,
                s.timestamp AS scan_timestamp,
                a.timestamp,
                a.detection_reason,
                a.risk_score,
                a.risk_label,
                a.pid,
                a.process_name,
                a.process_path,
                a.process_command_line,
                a.protocol,
                a.local_ip,
                a.local_port,
                a.remote_ip,
                a.remote_port,
                a.connection_state,
                a.intel_provider,
                a.intel_summary,
                a.metadata_json
            FROM alerts a
            INNER JOIN scans s ON s.id = a.scan_id
            {where_clause}
            ORDER BY a.timestamp DESC, a.risk_score DESC, a.id DESC
            LIMIT ?
        """
        params.append(limit)

        for database_path in self._candidate_paths(existing_only=True):
            with closing(self._connect(database_path)) as connection:
                self._ensure_schema(connection)
                rows = connection.execute(query, tuple(params)).fetchall()
            if not rows:
                continue
            self._active_database_path = database_path
            return [
                {
                    "alert_id": int(row["id"]),
                    "scan_id": int(row["scan_id"]),
                    "scan_timestamp": str(row["scan_timestamp"]),
                    **self._row_to_alert(row).to_dict(),
                }
                for row in rows
            ]
        return []

    def load_alert_groups(
        self,
        limit: int,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, object]]:
        if self._database_path is None or limit < 1:
            return []

        filters = []
        params: list[object] = []
        if risk_label:
            filters.append("risk_label = ?")
            params.append(risk_label.upper())
        if reason:
            filters.append("detection_reason = ?")
            params.append(reason)

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        query = f"""
            SELECT
                detection_reason,
                process_name,
                COALESCE(remote_ip, '') AS remote_ip,
                COALESCE(remote_port, -1) AS remote_port,
                COUNT(*) AS occurrence_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                MAX(risk_score) AS max_risk_score,
                MAX(CASE risk_label WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS risk_rank
            FROM alerts
            {where_clause}
            GROUP BY detection_reason, process_name, COALESCE(remote_ip, ''), COALESCE(remote_port, -1)
            ORDER BY occurrence_count DESC, max_risk_score DESC, last_seen DESC
            LIMIT ?
        """
        params.append(limit)

        risk_map = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}
        for database_path in self._candidate_paths(existing_only=True):
            with closing(self._connect(database_path)) as connection:
                self._ensure_schema(connection)
                rows = connection.execute(query, tuple(params)).fetchall()
            if not rows:
                continue
            self._active_database_path = database_path
            return [
                {
                    "detection_reason": str(row["detection_reason"]),
                    "process_name": str(row["process_name"]),
                    "remote_ip": str(row["remote_ip"]) or "",
                    "remote_port": None if int(row["remote_port"]) == -1 else int(row["remote_port"]),
                    "occurrence_count": int(row["occurrence_count"]),
                    "first_seen": str(row["first_seen"]),
                    "last_seen": str(row["last_seen"]),
                    "max_risk_score": int(row["max_risk_score"]),
                    "risk_label": risk_map.get(int(row["risk_rank"]), "LOW"),
                }
                for row in rows
            ]
        return []

    def get_storage_stats(self) -> dict[str, object]:
        if self._database_path is None:
            return {
                "backend": "disabled",
                "database_path": None,
                "scan_count": 0,
                "alert_count": 0,
                "fallback_active": False,
                "configured_database_path": None,
                "quarantined_paths": [],
            }

        for database_path in self._candidate_paths(existing_only=True):
            with closing(self._connect(database_path)) as connection:
                self._ensure_schema(connection)
                scan_count = int(connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
                alert_count = int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            self._active_database_path = database_path
            using_fallback = database_path != self._database_path
            self._using_fallback = using_fallback
            return {
                "backend": "sqlite",
                "database_path": str(database_path),
                "scan_count": scan_count,
                "alert_count": alert_count,
                "fallback_active": using_fallback,
                "configured_database_path": str(self._database_path),
                "quarantined_paths": list(self._quarantined_paths),
            }

        return {
            "backend": "sqlite",
            "database_path": str(self._active_database_path or self._database_path),
            "scan_count": 0,
            "alert_count": 0,
            "fallback_active": self._using_fallback,
            "configured_database_path": str(self._database_path),
            "quarantined_paths": list(self._quarantined_paths),
        }

    def _connect(self, database_path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(database_path, timeout=self._lock_timeout_seconds)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            # WAL suits one writer plus concurrent readers (CLI alongside the
            # service) and, unlike MEMORY, survives a crash mid-write.
            connection.execute("PRAGMA journal_mode = WAL")
        except BaseException:
            # A PRAGMA on an unusable file raises here. Closing explicitly stops
            # the handle leaking, which on Windows would also block the cleanup
            # that corruption recovery depends on.
            connection.close()
            raise
        return connection

    def _reset_database_files(self, database_path: Path | None) -> bool:
        if database_path is None:
            return False

        suffix = f".corrupt-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        candidates = [
            database_path,
            database_path.with_name(database_path.name + "-journal"),
            database_path.with_name(database_path.name + "-wal"),
            database_path.with_name(database_path.name + "-shm"),
        ]
        moved_any = False
        for candidate in candidates:
            if not candidate.exists():
                continue
            quarantine_path = candidate.with_name(candidate.name + suffix)
            try:
                candidate.replace(quarantine_path)
            except OSError:
                # Moving it aside is preferable, but a database we cannot read
                # and cannot move would block recovery entirely.
                try:
                    candidate.unlink()
                except OSError:
                    continue
                moved_any = True
                continue
            if candidate == database_path:
                self._quarantined_paths.append(str(quarantine_path))
            moved_any = True
        return moved_any

    def _candidate_paths(self, *, existing_only: bool = False) -> list[Path]:
        if self._database_path is None:
            return []

        candidates: list[Path] = []
        for candidate in (
            self._active_database_path,
            self._database_path,
            self._fallback_database_path(self._database_path),
        ):
            if candidate is None:
                continue
            if existing_only and not candidate.exists():
                continue
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    @staticmethod
    def _fallback_database_path(database_path: Path) -> Path:
        suffix = database_path.suffix or ".db"
        stem = database_path.stem if database_path.suffix else database_path.name
        return database_path.with_name(f"{stem}_fallback{suffix}")

    def _ensure_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                connection_count INTEGER NOT NULL,
                public_remote_ip_count INTEGER NOT NULL,
                collector_source TEXT NOT NULL,
                scan_duration_ms INTEGER NOT NULL,
                warnings_json TEXT NOT NULL,
                alert_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                detection_reason TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_label TEXT NOT NULL,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                process_command_line TEXT NOT NULL,
                protocol TEXT NOT NULL,
                local_ip TEXT NOT NULL,
                local_port INTEGER,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER,
                connection_state TEXT NOT NULL,
                intel_provider TEXT NOT NULL,
                intel_summary TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_reason ON alerts(detection_reason);
            CREATE INDEX IF NOT EXISTS idx_alerts_risk_label ON alerts(risk_label);
            CREATE INDEX IF NOT EXISTS idx_alerts_remote_ip ON alerts(remote_ip);
            """
        )

    @staticmethod
    def _load_json_list(raw_value: object) -> list[str]:
        if not raw_value:
            return []
        try:
            payload = json.loads(str(raw_value))
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list):
            return []
        return [str(item) for item in payload]

    @staticmethod
    def _load_json_dict(raw_value: object) -> dict[str, object]:
        if not raw_value:
            return {}
        try:
            payload = json.loads(str(raw_value))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            timestamp=str(row["timestamp"]),
            detection_reason=str(row["detection_reason"]),
            risk_score=int(row["risk_score"]),
            risk_label=str(row["risk_label"]),
            pid=int(row["pid"]),
            process_name=str(row["process_name"]),
            process_path=str(row["process_path"]),
            process_command_line=str(row["process_command_line"]),
            protocol=str(row["protocol"]),
            local_ip=str(row["local_ip"]),
            local_port=row["local_port"],
            remote_ip=str(row["remote_ip"]),
            remote_port=row["remote_port"],
            connection_state=str(row["connection_state"]),
            intel_provider=str(row["intel_provider"]),
            intel_summary=str(row["intel_summary"]),
            metadata=self._load_json_dict(row["metadata_json"]),
        )
