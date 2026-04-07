from __future__ import annotations

import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from hids.collector import ConnectionCollector
from hids.detector import Detector
from hids.logger import JsonAlertLogger
from hids.models import LogWriteResult, ScanResult
from hids.parser import is_public_ip
from hids.reporting import build_explained_alert, build_safe_share_report, default_safe_share_report_path
from hids.state import DetectionState


class HIDSService:
    def __init__(
        self,
        collector: ConnectionCollector,
        detector: Detector,
        export_logger: JsonAlertLogger,
        detection_state: DetectionState | None = None,
        state_path: Path | None = None,
        history_limit: int = 100,
    ) -> None:
        self._collector = collector
        self._detector = detector
        self._export_logger = export_logger
        self._state = detection_state or DetectionState()
        self._state_path = state_path
        self._history: deque[ScanResult] = deque(self._export_logger.load_recent_scans(history_limit), maxlen=history_limit)
        self._latest_result: ScanResult | None = self._history[-1] if self._history else None
        self._started_at = datetime.now(timezone.utc)
        self._lock = Lock()

    def run_scan(self) -> LogWriteResult | None:
        started = time.perf_counter()
        observed_at = datetime.now(timezone.utc)
        collection = self._collector.collect()
        alerts = self._detector.detect(collection.connections, self._state, observed_at)
        public_remote_ip_count = len(
            {
                connection.remote_ip
                for connection in collection.connections
                if connection.direction == "OUTBOUND" and connection.remote_ip and is_public_ip(connection.remote_ip)
            }
        )
        warnings = list(collection.warnings)

        try:
            self._state.save(self._state_path)
        except OSError as exc:
            warnings.append(f"state persistence failed: {exc}")

        result = ScanResult(
            timestamp=collection.timestamp,
            connection_count=len(collection.connections),
            public_remote_ip_count=public_remote_ip_count,
            alerts=alerts,
            collector_source=collection.source,
            scan_duration_ms=max(1, int((time.perf_counter() - started) * 1000)),
            warnings=warnings,
        )
        log_result: LogWriteResult | None = None
        try:
            log_result = self._export_logger.write_scan(result)
        except Exception as exc:
            result = ScanResult(
                timestamp=result.timestamp,
                connection_count=result.connection_count,
                public_remote_ip_count=result.public_remote_ip_count,
                alerts=result.alerts,
                collector_source=result.collector_source,
                scan_duration_ms=result.scan_duration_ms,
                warnings=[*warnings, f"log export failed: {exc}"],
            )

        with self._lock:
            self._latest_result = result
            self._history.append(result)

        return log_result

    def get_latest_result(self) -> ScanResult | None:
        with self._lock:
            return self._latest_result

    def get_latest_alerts(self, limit: int | None = None) -> list[dict[str, object]]:
        result = self.get_latest_result()
        if result is None:
            return []
        alerts = result.alerts if limit is None else result.alerts[:limit]
        return [alert.to_dict() for alert in alerts]

    def get_explained_latest_alerts(
        self,
        limit: int | None = None,
        *,
        redact_sensitive: bool = False,
    ) -> list[dict[str, object]]:
        result = self.get_latest_result()
        if result is None:
            return []
        alerts = result.alerts if limit is None else result.alerts[:limit]
        return [build_explained_alert(alert, redact_sensitive=redact_sensitive) for alert in alerts]

    def get_recent_scans(self, limit: int | None = None) -> list[dict[str, object]]:
        requested_limit = limit if limit is not None else max(1, self._history.maxlen or len(self._history) or 1)
        persisted_scans = self._export_logger.load_recent_scans(requested_limit)
        if persisted_scans:
            scans = persisted_scans
        else:
            with self._lock:
                scans = list(self._history)

        if limit is not None and limit > 0:
            scans = scans[-limit:]
        return [scan.to_dict() for scan in reversed(scans)]

    def get_alert_history(
        self,
        limit: int | None = None,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, object]]:
        requested_limit = 100 if limit is None else max(1, limit)
        persisted_alerts = self._export_logger.load_recent_alerts(
            requested_limit,
            risk_label=risk_label,
            reason=reason,
        )
        if persisted_alerts:
            return persisted_alerts

        result = self.get_latest_result()
        if result is None:
            return []
        alerts = [alert.to_dict() for alert in result.alerts]
        if risk_label:
            alerts = [alert for alert in alerts if str(alert.get("risk_label", "")).upper() == risk_label.upper()]
        if reason:
            alerts = [alert for alert in alerts if str(alert.get("detection_reason", "")) == reason]
        return alerts[:requested_limit]

    def get_explained_alert_history(
        self,
        limit: int | None = None,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
        redact_sensitive: bool = False,
    ) -> list[dict[str, object]]:
        alerts = self.get_alert_history(limit=limit, risk_label=risk_label, reason=reason)
        return [build_explained_alert(alert, redact_sensitive=redact_sensitive) for alert in alerts]

    def get_alert_groups(
        self,
        limit: int | None = None,
        *,
        risk_label: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, object]]:
        requested_limit = 20 if limit is None else max(1, limit)
        return self._export_logger.load_alert_groups(
            requested_limit,
            risk_label=risk_label,
            reason=reason,
        )

    def get_storage_stats(self) -> dict[str, object]:
        return self._export_logger.get_storage_stats()

    def get_summary(self) -> dict[str, object]:
        result = self.get_latest_result()
        if result is None:
            return {
                "status": "idle",
                "alerts": [],
                "timestamp": None,
                "uptime_seconds": int((datetime.now(timezone.utc) - self._started_at).total_seconds()),
                "history_count": 0,
                "storage": self.get_storage_stats(),
            }

        risk_breakdown = Counter(alert.risk_label for alert in result.alerts)
        return {
            "status": "ok",
            "timestamp": result.timestamp,
            "connection_count": result.connection_count,
            "public_remote_ip_count": result.public_remote_ip_count,
            "alert_count": len(result.alerts),
            "risk_breakdown": dict(risk_breakdown),
            "collector_source": result.collector_source,
            "scan_duration_ms": result.scan_duration_ms,
            "warnings": list(result.warnings),
            "warning_count": len(result.warnings),
            "uptime_seconds": int((datetime.now(timezone.utc) - self._started_at).total_seconds()),
            "history_count": len(self.get_recent_scans()),
            "storage": self.get_storage_stats(),
        }

    def get_health(self) -> dict[str, object]:
        latest = self.get_latest_result()
        return {
            "status": "ok",
            "started_at": self._started_at.isoformat(timespec="seconds"),
            "last_scan": None if latest is None else latest.timestamp,
            "collector_source": None if latest is None else latest.collector_source,
            "warning_count": 0 if latest is None else len(latest.warnings),
            "storage": self.get_storage_stats(),
        }

    def create_safe_share_report(
        self,
        *,
        alert_limit: int = 10,
        scan_limit: int = 5,
        group_limit: int = 5,
    ) -> str:
        return build_safe_share_report(
            self.get_latest_result(),
            self.get_summary(),
            self.get_alert_history(limit=alert_limit),
            self.get_recent_scans(limit=scan_limit),
            self.get_alert_groups(limit=group_limit),
        )

    def write_safe_share_report(
        self,
        destination: Path | None = None,
        *,
        alert_limit: int = 10,
        scan_limit: int = 5,
        group_limit: int = 5,
    ) -> Path:
        report = self.create_safe_share_report(
            alert_limit=alert_limit,
            scan_limit=scan_limit,
            group_limit=group_limit,
        )
        target_path = destination or default_safe_share_report_path()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(report, encoding="utf-8")
        return target_path
