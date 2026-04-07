from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RawConnection:
    protocol: str
    family: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    state: str
    pid: int


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    executable: str
    command_line: str


@dataclass(frozen=True)
class ConnectionRecord:
    timestamp: str
    protocol: str
    family: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    state: str
    pid: int
    process_name: str
    process_path: str
    process_command_line: str
    direction: str

    @property
    def local_endpoint(self) -> str:
        if self.local_port is None:
            return self.local_ip
        return f"{self.local_ip}:{self.local_port}"

    @property
    def remote_endpoint(self) -> str:
        if self.remote_port is None:
            return self.remote_ip
        return f"{self.remote_ip}:{self.remote_port}"

    @property
    def connection_key(self) -> tuple[int, str, str, int | None, str, int | None, str]:
        return (
            self.pid,
            self.protocol,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.state,
        )

    @property
    def behavior_key(self) -> tuple[int, str, str, int | None]:
        return (self.pid, self.process_name.lower(), self.remote_ip, self.remote_port)


@dataclass(frozen=True)
class CollectionResult:
    timestamp: str
    source: str
    connections: list[ConnectionRecord]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "connection_count": len(self.connections),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class ThreatIntelRecord:
    ip: str
    provider: str
    risk_label: str
    risk_score: int
    summary: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Alert:
    timestamp: str
    detection_reason: str
    risk_score: int
    risk_label: str
    pid: int
    process_name: str
    process_path: str
    process_command_line: str
    protocol: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    connection_state: str
    intel_provider: str
    intel_summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Alert":
        return cls(
            timestamp=str(payload.get("timestamp", "")),
            detection_reason=str(payload.get("detection_reason", "")),
            risk_score=int(payload.get("risk_score", 0)),
            risk_label=str(payload.get("risk_label", "LOW")),
            pid=int(payload.get("pid", -1)),
            process_name=str(payload.get("process_name", "Unknown")),
            process_path=str(payload.get("process_path", "")),
            process_command_line=str(payload.get("process_command_line", "")),
            protocol=str(payload.get("protocol", "")),
            local_ip=str(payload.get("local_ip", "")),
            local_port=payload.get("local_port"),
            remote_ip=str(payload.get("remote_ip", "")),
            remote_port=payload.get("remote_port"),
            connection_state=str(payload.get("connection_state", "")),
            intel_provider=str(payload.get("intel_provider", "")),
            intel_summary=str(payload.get("intel_summary", "")),
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(frozen=True)
class ScanResult:
    timestamp: str
    connection_count: int
    public_remote_ip_count: int
    alerts: list[Alert]
    collector_source: str = "unknown"
    scan_duration_ms: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "connection_count": self.connection_count,
            "public_remote_ip_count": self.public_remote_ip_count,
            "collector_source": self.collector_source,
            "scan_duration_ms": self.scan_duration_ms,
            "warnings": list(self.warnings),
            "alerts": [alert.to_dict() for alert in self.alerts],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanResult":
        return cls(
            timestamp=str(payload.get("timestamp", "")),
            connection_count=int(payload.get("connection_count", 0)),
            public_remote_ip_count=int(payload.get("public_remote_ip_count", 0)),
            alerts=[Alert.from_dict(item) for item in payload.get("alerts", [])],
            collector_source=str(payload.get("collector_source", "unknown")),
            scan_duration_ms=int(payload.get("scan_duration_ms", 0)),
            warnings=[str(item) for item in payload.get("warnings", [])],
        )


@dataclass(frozen=True)
class LogWriteResult:
    alert_path: Path | None = None
    scan_path: Path | None = None
    database_path: Path | None = None
