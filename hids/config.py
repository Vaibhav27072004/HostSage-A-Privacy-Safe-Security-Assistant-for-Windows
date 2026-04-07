from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_SUSPICIOUS_PORTS = {1337, 4444, 5555, 6666}
DEFAULT_SUSPICIOUS_PROCESSES = {"nc.exe", "ncat.exe", "psexec.exe", "netcat.exe", "socat.exe"}
DEFAULT_SUSPICIOUS_COMMAND_PATTERNS = {
    " -enc ",
    " -encodedcommand ",
    "frombase64string(",
    "downloadstring(",
    "invoke-expression",
    "invoke-webrequest",
    "iex(",
}


@dataclass
class ThreatIntelConfig:
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    cache_ttl_seconds: int = 3600
    timeout_seconds: int = 5
    max_retries: int = 1


@dataclass
class RuleConfig:
    suspicious_ports: set[int] = field(default_factory=lambda: set(DEFAULT_SUSPICIOUS_PORTS))
    suspicious_process_names: set[str] = field(default_factory=lambda: set(DEFAULT_SUSPICIOUS_PROCESSES))
    suspicious_command_line_patterns: set[str] = field(
        default_factory=lambda: set(DEFAULT_SUSPICIOUS_COMMAND_PATTERNS)
    )
    known_networks: list[str] = field(default_factory=list)
    known_network_files: list[str] = field(default_factory=list)
    outbound_connection_threshold: int = 20
    unique_ip_threshold: int = 12
    beacon_min_samples: int = 4
    beacon_jitter_seconds: float = 3.0
    medium_intel_threshold: int = 40
    high_intel_threshold: int = 75


@dataclass
class RuntimeConfig:
    interval_seconds: int = 5
    export_path: str | None = "logs"
    scan_log_path: str | None = "logs/scans.jsonl"
    database_path: str | None = "logs/hids_history.db"
    state_path: str | None = "logs/detection_state.json"
    history_limit: int = 100
    state_history_size: int = 20


@dataclass
class ApiConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 5000


@dataclass
class HIDSConfig:
    rules: RuleConfig = field(default_factory=RuleConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    api: ApiConfig = field(default_factory=ApiConfig)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _read_network_entries(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Known network file not found: {path}")

    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def _resolve_path(value: str | None, base_dir: Path) -> str | None:
    if not value:
        return value

    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return str(path)


def _resolve_paths(values: list[str], base_dir: Path) -> list[str]:
    return [str((base_dir / Path(value)).resolve()) if not Path(value).is_absolute() else str(Path(value)) for value in values]


def _apply_env_int(env_name: str, default: int) -> int:
    value = os.getenv(env_name)
    return default if value in {None, ""} else int(value)


def _apply_env_str(env_name: str, default: str) -> str:
    value = os.getenv(env_name)
    return default if value in {None, ""} else value


def load_config(path: Path) -> HIDSConfig:
    payload = _read_json(path)
    base_dir = path.resolve().parent if path else Path.cwd()

    config = HIDSConfig()

    rules = payload.get("rules", {})
    runtime = payload.get("runtime", {})
    threat_intel = payload.get("threat_intel", {})
    api = payload.get("api", {})

    config.rules.suspicious_ports = set(rules.get("suspicious_ports", config.rules.suspicious_ports))
    config.rules.suspicious_process_names = {
        item.lower() for item in rules.get("suspicious_process_names", config.rules.suspicious_process_names)
    }
    config.rules.suspicious_command_line_patterns = {
        item.lower()
        for item in rules.get(
            "suspicious_command_line_patterns",
            config.rules.suspicious_command_line_patterns,
        )
    }
    config.rules.known_networks = list(rules.get("known_networks", config.rules.known_networks))
    config.rules.known_network_files = _resolve_paths(
        list(rules.get("known_network_files", config.rules.known_network_files)),
        base_dir,
    )
    for file_path in config.rules.known_network_files:
        config.rules.known_networks.extend(_read_network_entries(Path(file_path)))
    config.rules.outbound_connection_threshold = int(
        rules.get("outbound_connection_threshold", config.rules.outbound_connection_threshold)
    )
    config.rules.unique_ip_threshold = int(rules.get("unique_ip_threshold", config.rules.unique_ip_threshold))
    config.rules.beacon_min_samples = int(rules.get("beacon_min_samples", config.rules.beacon_min_samples))
    config.rules.beacon_jitter_seconds = float(
        rules.get("beacon_jitter_seconds", config.rules.beacon_jitter_seconds)
    )
    config.rules.medium_intel_threshold = int(
        rules.get("medium_intel_threshold", config.rules.medium_intel_threshold)
    )
    config.rules.high_intel_threshold = int(rules.get("high_intel_threshold", config.rules.high_intel_threshold))

    config.runtime.interval_seconds = int(runtime.get("interval_seconds", config.runtime.interval_seconds))
    config.runtime.export_path = _resolve_path(runtime.get("export_path", config.runtime.export_path), base_dir)
    config.runtime.scan_log_path = _resolve_path(runtime.get("scan_log_path", config.runtime.scan_log_path), base_dir)
    config.runtime.database_path = _resolve_path(runtime.get("database_path", config.runtime.database_path), base_dir)
    config.runtime.state_path = _resolve_path(runtime.get("state_path", config.runtime.state_path), base_dir)
    config.runtime.history_limit = int(runtime.get("history_limit", config.runtime.history_limit))
    config.runtime.state_history_size = int(runtime.get("state_history_size", config.runtime.state_history_size))

    config.threat_intel.abuseipdb_api_key = str(
        threat_intel.get("abuseipdb_api_key", config.threat_intel.abuseipdb_api_key)
    )
    config.threat_intel.virustotal_api_key = str(
        threat_intel.get("virustotal_api_key", config.threat_intel.virustotal_api_key)
    )
    config.threat_intel.cache_ttl_seconds = int(
        threat_intel.get("cache_ttl_seconds", config.threat_intel.cache_ttl_seconds)
    )
    config.threat_intel.timeout_seconds = int(
        threat_intel.get("timeout_seconds", config.threat_intel.timeout_seconds)
    )
    config.threat_intel.max_retries = int(
        threat_intel.get("max_retries", config.threat_intel.max_retries)
    )

    config.api.enabled = bool(api.get("enabled", config.api.enabled))
    config.api.host = str(api.get("host", config.api.host))
    config.api.port = int(api.get("port", config.api.port))

    config.threat_intel.abuseipdb_api_key = _apply_env_str(
        "HIDS_ABUSEIPDB_API_KEY",
        config.threat_intel.abuseipdb_api_key,
    )
    config.threat_intel.virustotal_api_key = _apply_env_str(
        "HIDS_VIRUSTOTAL_API_KEY",
        config.threat_intel.virustotal_api_key,
    )
    config.runtime.interval_seconds = _apply_env_int("HIDS_INTERVAL_SECONDS", config.runtime.interval_seconds)
    config.runtime.history_limit = _apply_env_int("HIDS_HISTORY_LIMIT", config.runtime.history_limit)
    config.runtime.state_history_size = _apply_env_int(
        "HIDS_STATE_HISTORY_SIZE",
        config.runtime.state_history_size,
    )
    config.api.port = _apply_env_int("HIDS_API_PORT", config.api.port)
    config.api.host = _apply_env_str("HIDS_API_HOST", config.api.host)

    export_path = os.getenv("HIDS_EXPORT_PATH")
    if export_path:
        config.runtime.export_path = _resolve_path(export_path, Path.cwd())

    scan_log_path = os.getenv("HIDS_SCAN_LOG_PATH")
    if scan_log_path:
        config.runtime.scan_log_path = _resolve_path(scan_log_path, Path.cwd())

    database_path = os.getenv("HIDS_DATABASE_PATH")
    if database_path:
        config.runtime.database_path = _resolve_path(database_path, Path.cwd())

    state_path = os.getenv("HIDS_STATE_PATH")
    if state_path:
        config.runtime.state_path = _resolve_path(state_path, Path.cwd())

    return config
