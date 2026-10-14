from __future__ import annotations

import json
from collections import deque
from datetime import datetime
from pathlib import Path

from hids.models import LogWriteResult, ScanResult
from hids.storage import SQLiteHistoryStore


class JsonAlertLogger:
    def __init__(
        self,
        export_target: str | None,
        scan_log_target: str | None = None,
        database_path: str | None = None,
    ) -> None:
        self._export_target = export_target
        self._scan_log_target = scan_log_target
        self._resolved_alert_path: Path | None = None
        self._resolved_scan_path: Path | None = None
        self._history_store = SQLiteHistoryStore(database_path)

    def write_scan(self, result: ScanResult) -> LogWriteResult | None:
        alert_path = self._write_alerts(result)
        scan_path = self._write_scan_record(result)
        database_path = self._write_database_record(result)
        if alert_path is None and scan_path is None and database_path is None:
            return None
        return LogWriteResult(
            alert_path=alert_path,
            scan_path=scan_path,
            database_path=database_path,
        )

    def load_recent_scans(self, limit: int) -> list[ScanResult]:
        if self._history_store.enabled:
            try:
                results = self._history_store.load_recent_scans(limit)
            except Exception:
                results = []
            if results:
                return results

        if not self._scan_log_target or limit < 1:
            return []

        path = self._resolve_scan_path()
        if not path.exists():
            return []

        recent_lines: deque[str] = deque(maxlen=limit)
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    recent_lines.append(line)

        results: list[ScanResult] = []
        for line in recent_lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                results.append(ScanResult.from_dict(payload))
        return results

    def load_recent_alerts(
        self,
        limit: int,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, object]]:
        if self._history_store.enabled:
            try:
                return self._history_store.load_recent_alerts(limit, risk_label=risk_label, reason=reason)
            except Exception:
                return []
        return []

    def load_alert_groups(
        self,
        limit: int,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, object]]:
        if self._history_store.enabled:
            try:
                return self._history_store.load_alert_groups(limit, risk_label=risk_label, reason=reason)
            except Exception:
                return []
        return []

    def get_storage_stats(self) -> dict[str, object]:
        try:
            return self._history_store.get_storage_stats()
        except Exception as exc:
            return {
                "backend": "sqlite",
                "database_path": None,
                "scan_count": 0,
                "alert_count": 0,
                "fallback_active": False,
                "configured_database_path": None,
                "quarantined_paths": [],
                "error": str(exc),
            }

    def _write_alerts(self, result: ScanResult) -> Path | None:
        if not self._export_target or not result.alerts:
            return None

        destination = self._resolve_alert_path()
        destination.parent.mkdir(parents=True, exist_ok=True)

        with destination.open("a", encoding="utf-8") as handle:
            for alert in result.alerts:
                handle.write(json.dumps(alert.to_dict(), separators=(",", ":")) + "\n")

        return destination

    def _write_scan_record(self, result: ScanResult) -> Path | None:
        if not self._scan_log_target:
            return None

        destination = self._resolve_scan_path()
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result.to_dict(), separators=(",", ":")) + "\n")
        return destination

    def _write_database_record(self, result: ScanResult) -> Path | None:
        return self._history_store.write_scan(result)

    def _resolve_alert_path(self) -> Path:
        if self._resolved_alert_path is not None:
            return self._resolved_alert_path

        path = Path(self._export_target)
        if path.suffix:
            self._resolved_alert_path = path
            return path

        filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        self._resolved_alert_path = path / filename
        return self._resolved_alert_path

    def _resolve_scan_path(self) -> Path:
        if self._resolved_scan_path is not None:
            return self._resolved_scan_path

        path = Path(self._scan_log_target)
        if path.suffix:
            self._resolved_scan_path = path
            return path

        self._resolved_scan_path = path / "scans.jsonl"
        return self._resolved_scan_path
