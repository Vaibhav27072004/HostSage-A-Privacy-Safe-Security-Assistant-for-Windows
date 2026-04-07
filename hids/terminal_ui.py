from __future__ import annotations

import argparse
import os
import sys
import textwrap
import time
from collections import Counter
from pathlib import Path

from hids.config import HIDSConfig
from hids.models import LogWriteResult, ScanResult
from hids.reporting import build_explained_alert
from hids.service import HIDSService
from hids.windows_service import get_windows_service_status

TERMINAL_WIDTH = 78
TERMINAL_ALERT_LIMIT = 8
TERMINAL_HISTORY_LIMIT = 5


def supports_color(disable_color: bool) -> bool:
    if disable_color or os.getenv("NO_COLOR") is not None or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True

    try:
        import ctypes

        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        vt_flag = 0x0004
        if mode.value & vt_flag:
            return True
        return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | vt_flag))
    except Exception:
        return False


def style(text: str, code: str, *, color_enabled: bool) -> str:
    if not color_enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def humanize_reason(reason: str) -> str:
    return reason.replace("_", " ")


def shorten(value: str, width: int) -> str:
    cleaned = " ".join(value.split())
    if not cleaned:
        return "-"
    return textwrap.shorten(cleaned, width=width, placeholder="...")


def format_endpoint(ip_address: str | None, port: int | None) -> str:
    if not ip_address:
        return "-"
    return ip_address if port is None else f"{ip_address}:{port}"


def format_path(path_value: Path | str | None) -> str:
    return "Disabled" if path_value is None else str(path_value)


def build_header_lines(title: str, subtitle: str | None = None, *, color_enabled: bool) -> list[str]:
    divider = "=" * TERMINAL_WIDTH
    lines = [
        style(divider, "36", color_enabled=color_enabled),
        style(title, "1;36", color_enabled=color_enabled),
        style(divider, "36", color_enabled=color_enabled),
    ]
    if subtitle:
        lines.append(subtitle)
    return lines


def build_section_lines(title: str, *, color_enabled: bool) -> list[str]:
    return [
        "",
        style(title, "1;37", color_enabled=color_enabled),
        style("-" * min(TERMINAL_WIDTH, max(18, len(title))), "90", color_enabled=color_enabled),
    ]


def build_kv_lines(items: list[tuple[str, object]]) -> list[str]:
    width = max(len(label) for label, _ in items) if items else 0
    return [f"{label:<{width}} : {value}" for label, value in items]


def risk_badge(label: str, *, color_enabled: bool) -> str:
    normalized = label.upper()
    code = {"HIGH": "1;31", "MEDIUM": "1;33", "LOW": "1;32"}.get(normalized, "1;36")
    return style(normalized, code, color_enabled=color_enabled)


def status_badge(result: ScanResult, *, color_enabled: bool) -> str:
    if result.alerts:
        return style("ATTENTION NEEDED", "1;31", color_enabled=color_enabled)
    if result.warnings:
        return style("MONITOR WITH WARNINGS", "1;33", color_enabled=color_enabled)
    return style("HEALTHY", "1;32", color_enabled=color_enabled)


def build_scan_report_lines(
    result: ScanResult,
    log_result: LogWriteResult | None,
    *,
    color_enabled: bool,
) -> list[str]:
    risk_breakdown = Counter(alert.risk_label.upper() for alert in result.alerts)
    breakdown = ", ".join(f"{label}:{count}" for label, count in sorted(risk_breakdown.items())) or "none"
    lines = build_header_lines(
        "HostSage Scan Summary",
        f"Status: {status_badge(result, color_enabled=color_enabled)}",
        color_enabled=color_enabled,
    )
    lines.extend(
        build_kv_lines(
            [
                ("Timestamp", result.timestamp),
                ("Collector", result.collector_source),
                ("Scan duration", f"{result.scan_duration_ms} ms"),
                ("Connections", result.connection_count),
                ("Public IPs", result.public_remote_ip_count),
                ("Alerts", len(result.alerts)),
                ("Risk mix", breakdown),
            ]
        )
    )
    lines.extend(build_section_lines("Top Alerts", color_enabled=color_enabled))
    if not result.alerts:
        lines.append("No alerts were detected in this scan.")
    for index, alert in enumerate(result.alerts[:TERMINAL_ALERT_LIMIT], start=1):
        explained = build_explained_alert(alert)
        reason = shorten(humanize_reason(alert.detection_reason), 24)
        process = shorten(f"{alert.process_name} (PID {alert.pid})", 28)
        remote = format_endpoint(alert.remote_ip, alert.remote_port)
        lines.append(
            f"{index:>2}. [{risk_badge(alert.risk_label, color_enabled=color_enabled)}] "
            f"{reason:<24} {process:<28} -> {remote} | score {alert.risk_score}"
        )
        lines.append(f"    why: {shorten(str(explained.get('why_flagged', '')), 92)}")
        next_steps = list(explained.get("recommended_next_steps", []))
        if next_steps:
            lines.append(f"    next: {shorten(str(next_steps[0]), 92)}")
        if alert.intel_provider and alert.intel_provider.lower() != "disabled":
            lines.append(f"    intel: {shorten(f'{alert.intel_provider}: {alert.intel_summary}', 70)}")
    if len(result.alerts) > TERMINAL_ALERT_LIMIT:
        lines.append(f"... {len(result.alerts) - TERMINAL_ALERT_LIMIT} additional alerts not shown")
    if result.warnings:
        lines.extend(build_section_lines("Warnings", color_enabled=color_enabled))
        lines.extend(f"- {warning}" for warning in result.warnings)
    if log_result is not None:
        lines.extend(build_section_lines("Saved Output", color_enabled=color_enabled))
        lines.extend(
            build_kv_lines(
                [
                    ("Alert log", format_path(log_result.alert_path)),
                    ("Scan history", format_path(log_result.scan_path)),
                    ("SQLite history", format_path(log_result.database_path)),
                ]
            )
        )
    return lines


def build_recent_alert_lines(alerts: list[dict[str, object]], *, color_enabled: bool) -> list[str]:
    lines = build_header_lines(
        "Recent Alert History",
        "Newest alerts first with beginner-friendly explanations.",
        color_enabled=color_enabled,
    )
    if not alerts:
        lines.append("No alert history is currently available.")
        return lines
    for index, alert in enumerate(alerts, start=1):
        title = shorten(str(alert.get("explanation_title") or humanize_reason(str(alert.get("detection_reason", "")))), 42)
        process = shorten(f"{alert.get('process_name', 'unknown')} (PID {alert.get('pid', '-')})", 28)
        endpoint = format_endpoint(
            str(alert.get("remote_ip", "")) or None,
            alert.get("remote_port") if isinstance(alert.get("remote_port"), int) else None,
        )
        timestamp = str(alert.get("timestamp") or alert.get("scan_timestamp") or "-")
        lines.append(
            f"{index:>2}. [{risk_badge(str(alert.get('risk_label', 'LOW')), color_enabled=color_enabled)}] "
            f"{timestamp} | {title}"
        )
        lines.append(f"    process: {process} | remote: {endpoint}")
        lines.append(f"    why: {shorten(str(alert.get('why_flagged', '')), 92)}")
        next_steps = list(alert.get("recommended_next_steps", []))
        if next_steps:
            lines.append(f"    next: {shorten(str(next_steps[0]), 92)}")
        false_positive_hint = str(alert.get("false_positive_hint", ""))
        if false_positive_hint:
            lines.append(f"    note: {shorten(false_positive_hint, 92)}")
    return lines


def build_recent_scan_lines(scans: list[dict[str, object]], *, color_enabled: bool) -> list[str]:
    lines = build_header_lines("Recent Scan History", "Newest scans first.", color_enabled=color_enabled)
    if not scans:
        lines.append("No scan history is currently available.")
        return lines
    for index, scan in enumerate(scans, start=1):
        alert_count = scan.get("alert_count", len(scan.get("alerts", [])))
        lines.append(
            f"{index:>2}. {scan.get('timestamp', '-')}"
            f" | alerts={alert_count}"
            f" | connections={scan.get('connection_count', 0)}"
            f" | public_ips={scan.get('public_remote_ip_count', 0)}"
            f" | duration={scan.get('scan_duration_ms', 0)} ms"
            f" | source={scan.get('collector_source', 'unknown')}"
        )
    return lines


def build_config_overview_lines(
    config: HIDSConfig,
    config_path: str,
    storage_stats: dict[str, object],
    *,
    color_enabled: bool,
) -> list[str]:
    lines = build_header_lines(
        "Configuration and Storage",
        "Current runtime settings and saved-data locations.",
        color_enabled=color_enabled,
    )
    lines.extend(
        build_kv_lines(
            [
                ("Config file", Path(config_path).resolve()),
                ("Scan interval", f"{config.runtime.interval_seconds} seconds"),
                ("Outbound threshold", config.rules.outbound_connection_threshold),
                ("Unique IP threshold", config.rules.unique_ip_threshold),
                ("Trusted entries", len(config.rules.known_networks)),
                ("Trusted files", len(config.rules.known_network_files)),
                ("AbuseIPDB", "Enabled" if config.threat_intel.abuseipdb_api_key else "Disabled"),
                ("VirusTotal", "Enabled" if config.threat_intel.virustotal_api_key else "Disabled"),
                ("Alert export", format_path(config.runtime.export_path)),
                ("Scan log", format_path(config.runtime.scan_log_path)),
                ("State file", format_path(config.runtime.state_path)),
                ("DB backend", storage_stats.get("backend", "disabled")),
                ("DB path", storage_stats.get("database_path", "Disabled")),
                ("DB scans", storage_stats.get("scan_count", 0)),
                ("DB alerts", storage_stats.get("alert_count", 0)),
            ]
        )
    )
    return lines


def build_helpful_command_lines(config_path: str, *, color_enabled: bool) -> list[str]:
    lines = build_header_lines("Helpful Commands", "Useful shortcuts outside the menu.", color_enabled=color_enabled)
    lines.extend(
        [
            f"Quick scan      : python -m hids --config {config_path}",
            f"Guided terminal : python -m hids --terminal --config {config_path}",
            f"Safe report     : python -m hids --share-report --config {config_path}",
            f"Watch mode      : python -m hids --watch --interval 5 --iterations 0 --config {config_path}",
            f"API server      : python -m hids --serve-api --api-port 5000 --config {config_path}",
            f"Service install : python -m hids --service-install --config {config_path}",
            "Service status  : python -m hids --service-status",
        ]
    )
    if os.name == "nt":
        try:
            status = get_windows_service_status()
        except Exception:
            status = "unavailable"
        lines.extend(build_section_lines("Windows Service", color_enabled=color_enabled))
        lines.append(f"Current status: {status}")
    return lines


def print_lines(lines: list[str]) -> None:
    print("\n".join(lines))


def clear_screen() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def pause_for_enter() -> None:
    try:
        input("\nPress Enter to return to the menu...")
    except EOFError:
        return


def prompt_int(label: str, default: int, *, minimum: int) -> int:
    while True:
        try:
            raw_value = input(f"{label} [{default}]: ").strip()
        except EOFError:
            return default
        if not raw_value:
            return default
        try:
            value = int(raw_value)
        except ValueError:
            print("Please enter a whole number.")
            continue
        if value < minimum:
            print(f"Please enter a value greater than or equal to {minimum}.")
            continue
        return value


def build_terminal_home_lines(
    service: HIDSService,
    config: HIDSConfig,
    config_path: str,
    *,
    color_enabled: bool,
) -> list[str]:
    summary = service.get_summary()
    storage = summary.get("storage", {})
    lines = build_header_lines(
        "HostSage Terminal",
        "Friendly control center for monitoring, explainable alerts, and safe sharing.",
        color_enabled=color_enabled,
    )
    lines.extend(
        build_kv_lines(
            [
                ("Config", Path(config_path).resolve()),
                ("Last scan", summary.get("timestamp") or "No scans yet in this session"),
                ("Alerts in last scan", summary.get("alert_count", 0)),
                ("Warnings in last scan", summary.get("warning_count", 0)),
                ("Default interval", f"{config.runtime.interval_seconds} seconds"),
                ("Stored scans", storage.get("scan_count", 0)),
                ("Stored alerts", storage.get("alert_count", 0)),
            ]
        )
    )
    lines.extend(build_section_lines("Choose an Action", color_enabled=color_enabled))
    lines.extend(
        [
            "1. Run a quick scan now",
            "2. Start guided monitoring",
            "3. Review recent alerts with explanations",
            "4. Review recent scans",
            "5. Create safe share report",
            "6. View configuration and storage",
            "7. Show helpful commands",
            "0. Exit",
        ]
    )
    return lines


def build_safe_report_created_lines(report_path: Path, *, color_enabled: bool) -> list[str]:
    lines = build_header_lines(
        "Safe Share Report Created",
        "Sensitive machine details were redacted for safer sharing.",
        color_enabled=color_enabled,
    )
    lines.extend(
        build_kv_lines(
            [
                ("Report path", report_path.resolve()),
                ("Redacted", "local IPs, raw remote IPs, full paths, full command lines"),
            ]
        )
    )
    lines.extend(build_section_lines("Before Sharing", color_enabled=color_enabled))
    lines.extend(
        [
            "- Review the Markdown file once before sending it outside your team.",
            "- If you need to share raw indicators, send them separately through a secure channel.",
        ]
    )
    return lines


def run_terminal(
    service: HIDSService,
    config: HIDSConfig,
    args: argparse.Namespace,
    *,
    color_enabled: bool,
    run_loop_fn,
    print_scan_result_fn,
) -> int:
    if not sys.stdin.isatty():
        print("--terminal requires an interactive terminal session.", file=sys.stderr)
        return 2

    while True:
        clear_screen()
        print_lines(build_terminal_home_lines(service, config, args.config, color_enabled=color_enabled))
        try:
            choice = input("\nChoose an option [1]: ").strip().lower()
        except EOFError:
            print()
            return 0

        if choice in {"", "1", "scan"}:
            clear_screen()
            print(style("Running a quick scan...", "1;36", color_enabled=color_enabled))
            print()
            log_result = service.run_scan()
            print_scan_result_fn(service, log_result, color_enabled=color_enabled)
            pause_for_enter()
            continue
        if choice in {"2", "monitor", "watch"}:
            clear_screen()
            interval = prompt_int("Scan interval in seconds", config.runtime.interval_seconds, minimum=1)
            iterations = prompt_int("Number of scans (0 runs until Ctrl+C)", 0, minimum=0)
            print("\nMonitoring started. Press Ctrl+C to stop and return to the menu.\n")
            try:
                run_loop_fn(service, interval, iterations, color_enabled=color_enabled)
            except KeyboardInterrupt:
                print("\nMonitoring stopped. Returning to the menu.")
            pause_for_enter()
            continue
        if choice in {"3", "alerts"}:
            clear_screen()
            print_lines(
                build_recent_alert_lines(
                    service.get_explained_alert_history(limit=10),
                    color_enabled=color_enabled,
                )
            )
            pause_for_enter()
            continue
        if choice in {"4", "history", "scans"}:
            clear_screen()
            print_lines(build_recent_scan_lines(service.get_recent_scans(limit=TERMINAL_HISTORY_LIMIT), color_enabled=color_enabled))
            pause_for_enter()
            continue
        if choice in {"5", "report", "share"}:
            clear_screen()
            print(style("Running a fresh scan before creating the safe report...", "1;36", color_enabled=color_enabled))
            print()
            service.run_scan()
            report_path = service.write_safe_share_report()
            print_lines(build_safe_report_created_lines(report_path, color_enabled=color_enabled))
            pause_for_enter()
            continue
        if choice in {"6", "config"}:
            clear_screen()
            print_lines(build_config_overview_lines(config, args.config, service.get_storage_stats(), color_enabled=color_enabled))
            pause_for_enter()
            continue
        if choice in {"7", "help", "commands"}:
            clear_screen()
            print_lines(build_helpful_command_lines(args.config, color_enabled=color_enabled))
            pause_for_enter()
            continue
        if choice in {"0", "q", "quit", "exit"}:
            print("Exiting HostSage terminal.")
            return 0
        print("Unknown choice. Please select one of the listed options.")
        time.sleep(1.2)
