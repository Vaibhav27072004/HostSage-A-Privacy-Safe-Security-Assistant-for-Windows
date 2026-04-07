from __future__ import annotations

import ipaddress
from typing import Any

from hids.models import RawConnection


def split_address(address: str) -> tuple[str, int | None]:
    cleaned = address.strip()

    if not cleaned:
        return "", None
    if cleaned == "*":
        return "*", None
    if cleaned == "*:*":
        return "*", None
    if cleaned.startswith("[") and "]:" in cleaned:
        host, port = cleaned[1:].rsplit("]:", 1)
        return host, parse_port(port)
    if ":" in cleaned:
        host, port = cleaned.rsplit(":", 1)
        return host, parse_port(port)
    return cleaned, None


def parse_port(port_value: str | int | None) -> int | None:
    if port_value in {None, "", "*"}:
        return None
    try:
        return int(port_value)
    except (TypeError, ValueError):
        return None


def normalize_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_public_ip(host: str) -> bool:
    ip_value = normalize_ip(host)
    return bool(ip_value and ip_value.is_global)


def is_local_or_unspecified(host: str) -> bool:
    if host in {"", "*"}:
        return True
    ip_value = normalize_ip(host)
    if ip_value is None:
        return host.lower() == "localhost"
    return ip_value.is_loopback or ip_value.is_unspecified


def ip_in_networks(host: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    ip_value = normalize_ip(host)
    if ip_value is None:
        return False
    return any(ip_value in network for network in networks)


def load_networks(values: list[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        entry = value.strip()
        if not entry:
            continue
        if "/" not in entry:
            ip_value = ipaddress.ip_address(entry)
            prefix = 32 if ip_value.version == 4 else 128
            entry = f"{entry}/{prefix}"
        networks.append(ipaddress.ip_network(entry, strict=False))
    return networks


def infer_direction(
    local_ip: str,
    local_port: int | None,
    remote_ip: str,
    remote_port: int | None,
    state: str,
) -> str:
    if state.upper() == "LISTENING" or not remote_ip:
        return "LISTENING"
    if is_local_or_unspecified(local_ip) and is_local_or_unspecified(remote_ip):
        return "LOCAL"
    if local_port is not None and local_port >= 49152 and (remote_port or 0) < 49152:
        return "OUTBOUND"
    if remote_port is not None and remote_port >= 49152 and (local_port or 0) < 49152:
        return "INBOUND"
    return "OUTBOUND"


def parse_psutil_address(address: Any) -> tuple[str, int | None]:
    if not address:
        return "", None
    if hasattr(address, "ip") and hasattr(address, "port"):
        return str(address.ip), parse_port(address.port)
    if isinstance(address, tuple):
        if len(address) >= 2:
            return str(address[0]), parse_port(address[1])
        if len(address) == 1:
            return str(address[0]), None
    return str(address), None


def parse_netstat_output(output: str) -> list[RawConnection]:
    records: list[RawConnection] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Active Connections") or line.startswith("Proto"):
            continue

        parts = line.split()
        if not parts:
            continue

        protocol = parts[0].upper()
        if protocol == "TCP" and len(parts) >= 5:
            local_address, remote_address, state, pid_raw = parts[1], parts[2], parts[3], parts[4]
        elif protocol == "UDP" and len(parts) >= 4:
            local_address, remote_address, pid_raw = parts[1], parts[2], parts[3]
            state = "STATELESS"
        else:
            continue

        local_ip, local_port = split_address(local_address)
        remote_ip, remote_port = split_address(remote_address)
        family = "IPv6" if ":" in local_ip and "." not in local_ip else "IPv4"

        try:
            pid = int(pid_raw)
        except ValueError:
            pid = -1

        records.append(
            RawConnection(
                protocol=protocol,
                family=family,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid,
            )
        )

    return records
