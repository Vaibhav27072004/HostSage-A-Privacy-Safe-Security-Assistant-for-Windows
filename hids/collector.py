from __future__ import annotations

import socket
import subprocess
from datetime import datetime, timezone

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from hids.models import CollectionResult, ConnectionRecord, ProcessInfo
from hids.parser import infer_direction, parse_netstat_output, parse_psutil_address


class ConnectionCollector:
    def __init__(self) -> None:
        self._process_cache: dict[int, ProcessInfo] = {}

    def collect(self) -> CollectionResult:
        observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        warnings: list[str] = []

        if psutil is not None:
            try:
                records = self._collect_with_psutil(observed_at)
                return CollectionResult(timestamp=observed_at, source="psutil", connections=records, warnings=warnings)
            except Exception as exc:
                warnings.append(f"psutil collection failed: {exc.__class__.__name__}: {exc}")

        try:
            records = self._collect_with_netstat(observed_at)
            return CollectionResult(timestamp=observed_at, source="netstat", connections=records, warnings=warnings)
        except Exception as exc:
            detail = "; ".join(warnings) if warnings else "no prior collector warnings"
            raise RuntimeError(
                f"Unable to collect connections. netstat failed with {exc.__class__.__name__}: {exc}. "
                f"Previous collector state: {detail}."
            ) from exc

    def _collect_with_psutil(self, observed_at: str) -> list[ConnectionRecord]:
        records: list[ConnectionRecord] = []

        for connection in psutil.net_connections(kind="inet"):
            protocol = self._infer_protocol(connection.type)
            family = self._infer_family(connection.family)
            local_ip, local_port = parse_psutil_address(connection.laddr)
            remote_ip, remote_port = parse_psutil_address(connection.raddr)
            pid = connection.pid or -1
            process_info = self._resolve_process(pid)
            state = connection.status or "STATELESS"
            direction = infer_direction(local_ip, local_port, remote_ip, remote_port, state)

            records.append(
                ConnectionRecord(
                    timestamp=observed_at,
                    protocol=protocol,
                    family=family,
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    process_name=process_info.name,
                    process_path=process_info.executable,
                    process_command_line=process_info.command_line,
                    direction=direction,
                )
            )

        return records

    def _collect_with_netstat(self, observed_at: str) -> list[ConnectionRecord]:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        records: list[ConnectionRecord] = []

        for connection in parse_netstat_output(result.stdout):
            process_info = self._resolve_process(connection.pid)
            direction = infer_direction(
                connection.local_ip,
                connection.local_port,
                connection.remote_ip,
                connection.remote_port,
                connection.state,
            )
            records.append(
                ConnectionRecord(
                    timestamp=observed_at,
                    protocol=connection.protocol,
                    family=connection.family,
                    local_ip=connection.local_ip,
                    local_port=connection.local_port,
                    remote_ip=connection.remote_ip,
                    remote_port=connection.remote_port,
                    state=connection.state,
                    pid=connection.pid,
                    process_name=process_info.name,
                    process_path=process_info.executable,
                    process_command_line=process_info.command_line,
                    direction=direction,
                )
            )

        return records

    def _resolve_process(self, pid: int) -> ProcessInfo:
        if pid in self._process_cache:
            return self._process_cache[pid]

        if psutil is None or pid <= 0:
            process_info = ProcessInfo(pid=pid, name="Unknown", executable="", command_line="")
            self._process_cache[pid] = process_info
            return process_info

        try:
            process = psutil.Process(pid)
            with process.oneshot():
                process_info = ProcessInfo(
                    pid=pid,
                    name=process.name(),
                    executable=process.exe() if process.exe() else "",
                    command_line=" ".join(process.cmdline()),
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_info = ProcessInfo(pid=pid, name="Unknown", executable="", command_line="")

        self._process_cache[pid] = process_info
        return process_info

    @staticmethod
    def _infer_protocol(socket_type: socket.SocketKind) -> str:
        if socket_type == socket.SOCK_STREAM:
            return "TCP"
        if socket_type == socket.SOCK_DGRAM:
            return "UDP"
        return str(socket_type)

    @staticmethod
    def _infer_family(family: socket.AddressFamily) -> str:
        if family == socket.AF_INET6:
            return "IPv6"
        if family == socket.AF_INET:
            return "IPv4"
        return str(family)
