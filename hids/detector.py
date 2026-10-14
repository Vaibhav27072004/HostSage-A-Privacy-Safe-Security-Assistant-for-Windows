from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from hids.config import RuleConfig
from hids.intel import ThreatIntelClient
from hids.models import Alert, ConnectionRecord, ThreatIntelRecord
from hids.parser import ip_in_networks, is_public_ip, load_networks
from hids.state import DetectionState


REASON_SCORES = {
    "suspicious_port": 70,
    "suspicious_process": 75,
    "suspicious_command_line": 82,
    "high_frequency_outbound": 65,
    "process_many_unique_ips": 60,
    "periodic_beacon": 85,
    "high_risk_ip": 80,
    "medium_risk_ip": 55,
}


class Detector:
    def __init__(self, config: RuleConfig, intel_client: ThreatIntelClient) -> None:
        self._config = config
        self._intel_client = intel_client
        self._known_networks = load_networks(config.known_networks)

    def detect(
        self,
        connections: list[ConnectionRecord],
        state: DetectionState,
        observed_at: datetime | None = None,
    ) -> list[Alert]:
        observed_at = observed_at or datetime.now(timezone.utc)
        timestamp = observed_at.isoformat(timespec="seconds")
        new_beacon_events = state.record_scan(connections, observed_at)
        alerts: list[Alert] = []
        intel_cache: dict[str, ThreatIntelRecord] = {}

        public_outbound = [
            connection
            for connection in connections
            if connection.direction == "OUTBOUND"
            and connection.remote_ip
            and is_public_ip(connection.remote_ip)
            and not self._is_known_network(connection.remote_ip)
        ]

        alerts.extend(self._detect_connection_rules(public_outbound, timestamp, intel_cache))
        alerts.extend(self._detect_outbound_volume(public_outbound, timestamp, intel_cache))
        alerts.extend(self._detect_process_spread(public_outbound, timestamp, intel_cache))
        alerts.extend(self._detect_periodic_beacons(public_outbound, new_beacon_events, state, timestamp, intel_cache))
        alerts.extend(self._detect_threat_intel(public_outbound, timestamp, intel_cache))

        deduplicated: dict[tuple[str, int, str, int | None], Alert] = {}
        for alert in alerts:
            key = (alert.detection_reason, alert.pid, alert.remote_ip, alert.remote_port)
            previous = deduplicated.get(key)
            if previous is None or alert.risk_score > previous.risk_score:
                deduplicated[key] = alert

        return sorted(deduplicated.values(), key=lambda alert: alert.risk_score, reverse=True)

    def _detect_connection_rules(
        self,
        connections: list[ConnectionRecord],
        timestamp: str,
        intel_cache: dict[str, ThreatIntelRecord],
    ) -> list[Alert]:
        alerts: list[Alert] = []
        for connection in connections:
            suspicious_port = self._find_suspicious_port(connection)
            if suspicious_port is not None:
                alerts.append(
                    self._build_alert(
                        connection=connection,
                        timestamp=timestamp,
                        reason="suspicious_port",
                        intel_record=self._lookup_intel(connection.remote_ip, intel_cache),
                        metadata={"matched_port": suspicious_port},
                    )
                )

            if self._matches_suspicious_process(connection):
                alerts.append(
                    self._build_alert(
                        connection=connection,
                        timestamp=timestamp,
                        reason="suspicious_process",
                        intel_record=self._lookup_intel(connection.remote_ip, intel_cache),
                        metadata={"process_path": connection.process_path},
                    )
                )

            suspicious_pattern = self._find_suspicious_command_line_pattern(connection)
            if suspicious_pattern is not None:
                alerts.append(
                    self._build_alert(
                        connection=connection,
                        timestamp=timestamp,
                        reason="suspicious_command_line",
                        intel_record=self._lookup_intel(connection.remote_ip, intel_cache),
                        metadata={"matched_pattern": suspicious_pattern},
                    )
                )

        return alerts

    def _detect_outbound_volume(
        self,
        connections: list[ConnectionRecord],
        timestamp: str,
        intel_cache: dict[str, ThreatIntelRecord],
    ) -> list[Alert]:
        grouped: dict[int, list[ConnectionRecord]] = defaultdict(list)
        for connection in connections:
            grouped[connection.pid].append(connection)

        alerts: list[Alert] = []
        for process_connections in grouped.values():
            if len(process_connections) < self._config.outbound_connection_threshold:
                continue
            exemplar = process_connections[0]
            alerts.append(
                self._build_alert(
                    connection=exemplar,
                    timestamp=timestamp,
                    reason="high_frequency_outbound",
                    intel_record=self._lookup_intel(exemplar.remote_ip, intel_cache),
                    metadata={"connection_count": len(process_connections)},
                )
            )
        return alerts

    def _detect_process_spread(
        self,
        connections: list[ConnectionRecord],
        timestamp: str,
        intel_cache: dict[str, ThreatIntelRecord],
    ) -> list[Alert]:
        grouped: dict[int, list[ConnectionRecord]] = defaultdict(list)
        for connection in connections:
            grouped[connection.pid].append(connection)

        alerts: list[Alert] = []
        for process_connections in grouped.values():
            unique_ips = sorted({connection.remote_ip for connection in process_connections})
            if len(unique_ips) < self._config.unique_ip_threshold:
                continue
            exemplar = process_connections[0]
            alerts.append(
                self._build_alert(
                    connection=exemplar,
                    timestamp=timestamp,
                    reason="process_many_unique_ips",
                    intel_record=self._lookup_intel(exemplar.remote_ip, intel_cache),
                    metadata={"unique_ip_count": len(unique_ips), "sample_ips": unique_ips[:10]},
                )
            )
        return alerts

    def _detect_periodic_beacons(
        self,
        connections: list[ConnectionRecord],
        new_beacon_events: set[tuple[int, str, str, int | None]],
        state: DetectionState,
        timestamp: str,
        intel_cache: dict[str, ThreatIntelRecord],
    ) -> list[Alert]:
        alerts: list[Alert] = []
        for connection in connections:
            if connection.behavior_key not in new_beacon_events:
                continue

            history = state.get_beacon_history(connection)
            if len(history) < self._config.beacon_min_samples:
                continue
            if not self._looks_periodic(history):
                continue

            intervals = [round(history[index] - history[index - 1], 2) for index in range(1, len(history))]
            alerts.append(
                self._build_alert(
                    connection=connection,
                    timestamp=timestamp,
                    reason="periodic_beacon",
                    intel_record=self._lookup_intel(connection.remote_ip, intel_cache),
                    metadata={"intervals_seconds": intervals},
                )
            )

        return alerts

    def _detect_threat_intel(
        self,
        connections: list[ConnectionRecord],
        timestamp: str,
        intel_cache: dict[str, ThreatIntelRecord],
    ) -> list[Alert]:
        alerts: list[Alert] = []
        by_remote_ip: dict[str, list[ConnectionRecord]] = defaultdict(list)
        for connection in connections:
            by_remote_ip[connection.remote_ip].append(connection)

        for remote_ip, ip_connections in by_remote_ip.items():
            intel_record = self._lookup_intel(remote_ip, intel_cache)
            if intel_record.risk_score >= self._config.high_intel_threshold:
                reason = "high_risk_ip"
            elif intel_record.risk_score >= self._config.medium_intel_threshold:
                reason = "medium_risk_ip"
            else:
                continue

            exemplar = ip_connections[0]
            alerts.append(
                self._build_alert(
                    connection=exemplar,
                    timestamp=timestamp,
                    reason=reason,
                    intel_record=intel_record,
                    metadata={"connection_count": len(ip_connections)},
                )
            )

        return alerts

    def _matches_suspicious_process(self, connection: ConnectionRecord) -> bool:
        haystack = " ".join(part.lower() for part in (connection.process_name, connection.process_path) if part)
        return any(pattern in haystack for pattern in self._config.suspicious_process_names)

    def _find_suspicious_command_line_pattern(self, connection: ConnectionRecord) -> str | None:
        command_line = (connection.process_command_line or "").lower()
        for pattern in self._config.suspicious_command_line_patterns:
            if pattern in command_line:
                return pattern
        return None

    def _find_suspicious_port(self, connection: ConnectionRecord) -> int | None:
        for port in (connection.local_port, connection.remote_port):
            if port is not None and port in self._config.suspicious_ports:
                return port
        return None

    def _lookup_intel(
        self,
        ip_address: str,
        intel_cache: dict[str, ThreatIntelRecord],
    ) -> ThreatIntelRecord:
        if ip_address not in intel_cache:
            intel_cache[ip_address] = self._intel_client.lookup(ip_address)
        return intel_cache[ip_address]

    def _build_alert(
        self,
        connection: ConnectionRecord,
        timestamp: str,
        reason: str,
        intel_record: ThreatIntelRecord,
        metadata: dict[str, object],
    ) -> Alert:
        base_score = REASON_SCORES[reason]
        risk_score = min(100, base_score + round(intel_record.risk_score * 0.25))
        risk_label = "HIGH" if risk_score >= 75 else "MEDIUM" if risk_score >= 40 else "LOW"

        return Alert(
            timestamp=timestamp,
            detection_reason=reason,
            risk_score=risk_score,
            risk_label=risk_label,
            pid=connection.pid,
            process_name=connection.process_name or "Unknown",
            process_path=connection.process_path,
            process_command_line=connection.process_command_line,
            protocol=connection.protocol,
            local_ip=connection.local_ip,
            local_port=connection.local_port,
            remote_ip=connection.remote_ip,
            remote_port=connection.remote_port,
            connection_state=connection.state,
            intel_provider=intel_record.provider,
            intel_summary=intel_record.summary,
            metadata=metadata,
        )

    def _looks_periodic(self, history: list[float]) -> bool:
        intervals = [history[index] - history[index - 1] for index in range(1, len(history))]
        if len(intervals) < self._config.beacon_min_samples - 1:
            return False

        # Samples that arrive faster than one beacon interval are not check-ins.
        # Without this guard a run of identical timestamps yields intervals of
        # zero, which satisfies any jitter tolerance and flags ordinary clients
        # that hold several sockets open to the same endpoint.
        minimum_interval = self._config.beacon_min_interval_seconds
        if any(interval < minimum_interval for interval in intervals):
            return False

        average = sum(intervals) / len(intervals)
        if average < minimum_interval:
            return False
        return all(abs(interval - average) <= self._config.beacon_jitter_seconds for interval in intervals)

    def _is_known_network(self, ip_address: str) -> bool:
        return bool(self._known_networks and ip_in_networks(ip_address, self._known_networks))
