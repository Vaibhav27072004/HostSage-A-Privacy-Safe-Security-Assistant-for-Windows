from __future__ import annotations

import argparse
import textwrap
import sys
import threading
import time
from pathlib import Path

from hids.api import create_app
from hids.config import HIDSConfig, load_config
from hids.models import LogWriteResult
from hids.runtime import build_monitoring_service
from hids.service import HIDSService
from hids.terminal_ui import build_scan_report_lines, run_terminal, supports_color
from hids.windows_service import (
    DEFAULT_SERVICE_NAME,
    get_windows_service_status,
    install_windows_service,
    remove_windows_service,
    start_windows_service,
    stop_windows_service,
)

try:
    from waitress import serve as waitress_serve
except ImportError:  # pragma: no cover
    waitress_serve = None


DEFAULT_CONFIG_PATH = "config.example.json"


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "HostSage: A Privacy-Safe Security Assistant for Windows with guided terminal mode, "
            "single scans, continuous monitoring, and optional API/service controls."
        ),
        epilog=textwrap.dedent(
            f"""\
            Examples:
              hostsage --terminal
              python -m hids --terminal
              hostsage --share-report
              python -m hids --share-report
              python -m hids --watch --interval 5 --iterations 0
              python -m hids --config config.json --threshold 15
              python -m hids --serve-api --api-port 5000
              python -m hids --service-install --config {DEFAULT_CONFIG_PATH}
            """
        ),
        formatter_class=HelpFormatter,
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to a JSON configuration file.",
    )
    parser.add_argument(
        "--terminal",
        action="store_true",
        help="Launch a guided interactive terminal for scans, monitoring, and history review.",
    )
    parser.add_argument(
        "--share-report",
        nargs="?",
        const="auto",
        default=None,
        help="Create a privacy-safe Markdown report. Optionally provide a custom output path.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Keep scanning on a timer instead of running once.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Seconds between scans in watch mode.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of scans to run in watch mode. Use 0 for continuous monitoring.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Override the outbound connection threshold for anomaly detection.",
    )
    parser.add_argument(
        "--export",
        default=None,
        help="Export alerts to a JSONL file or to a directory such as 'logs'.",
    )
    parser.add_argument(
        "--scan-log",
        default=None,
        help="Path to the scan history JSONL file.",
    )
    parser.add_argument(
        "--database",
        default=None,
        help="Path to the SQLite history database file.",
    )
    parser.add_argument(
        "--state-file",
        default=None,
        help="Path to the persisted detection state file.",
    )
    parser.add_argument(
        "--history-limit",
        type=int,
        default=None,
        help="Maximum number of recent scans kept in memory and exposed by the API.",
    )
    parser.add_argument(
        "--known-ips-file",
        default=None,
        help="Optional file containing trusted public IPs or CIDR ranges, one per line.",
    )
    parser.add_argument(
        "--serve-api",
        action="store_true",
        help="Start the optional HTTP API to expose alerts and scan history.",
    )
    parser.add_argument(
        "--api-host",
        default=None,
        help=(
            "Override the API bind host. The API is unauthenticated, so keep it on 127.0.0.1 "
            "unless you have placed it behind your own authenticated proxy."
        ),
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=None,
        help="Override the API bind port.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in the terminal and scan summaries.",
    )
    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument(
        "--service-install",
        action="store_true",
        help=f"Install the detector as the Windows Service '{DEFAULT_SERVICE_NAME}'.",
    )
    service_group.add_argument(
        "--service-remove",
        action="store_true",
        help=f"Remove the Windows Service '{DEFAULT_SERVICE_NAME}'.",
    )
    service_group.add_argument(
        "--service-start",
        action="store_true",
        help=f"Start the Windows Service '{DEFAULT_SERVICE_NAME}'.",
    )
    service_group.add_argument(
        "--service-stop",
        action="store_true",
        help=f"Stop the Windows Service '{DEFAULT_SERVICE_NAME}'.",
    )
    service_group.add_argument(
        "--service-status",
        action="store_true",
        help=f"Show the current status of the Windows Service '{DEFAULT_SERVICE_NAME}'.",
    )
    parser.add_argument(
        "--service-startup",
        choices=("auto", "manual", "disabled"),
        default="auto",
        help="Startup type used with --service-install.",
    )
    parser.add_argument(
        "--service-install-start",
        action="store_true",
        help="Start the Windows Service immediately after installing it.",
    )
    return parser


def _load_known_network_entries(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Known IP file not found: {path}")

    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def _resolve_optional_path(path_value: str | None) -> str | None:
    if not path_value:
        return None
    path = Path(path_value)
    return str(path if path.is_absolute() else (Path.cwd() / path))


def apply_cli_overrides(config: HIDSConfig, args: argparse.Namespace) -> HIDSConfig:
    if args.interval is not None:
        config.runtime.interval_seconds = args.interval
    if args.threshold is not None:
        config.rules.outbound_connection_threshold = args.threshold
    if args.export is not None:
        config.runtime.export_path = _resolve_optional_path(args.export)
    if args.scan_log is not None:
        config.runtime.scan_log_path = _resolve_optional_path(args.scan_log)
    if args.database is not None:
        config.runtime.database_path = _resolve_optional_path(args.database)
    if args.state_file is not None:
        config.runtime.state_path = _resolve_optional_path(args.state_file)
    if args.history_limit is not None:
        config.runtime.history_limit = args.history_limit
    if args.api_host is not None:
        config.api.host = args.api_host
    if args.api_port is not None:
        config.api.port = args.api_port
    if args.serve_api:
        config.api.enabled = True
    if args.known_ips_file is not None:
        known_ips_path = Path(_resolve_optional_path(args.known_ips_file))
        config.rules.known_network_files.append(str(known_ips_path))
        config.rules.known_networks.extend(_load_known_network_entries(known_ips_path))
    return config


def print_scan_result(
    service: HIDSService,
    log_result: LogWriteResult | None,
    *,
    color_enabled: bool,
) -> None:
    result = service.get_latest_result()
    if result is None:
        return

    print("\n".join(build_scan_report_lines(result, log_result, color_enabled=color_enabled)))


def run_loop(
    service: HIDSService,
    interval_seconds: int,
    iterations: int,
    *,
    color_enabled: bool,
) -> int:
    scan_count = 0

    while True:
        log_result = service.run_scan()
        print_scan_result(service, log_result, color_enabled=color_enabled)

        scan_count += 1
        if iterations != 0 and scan_count >= iterations:
            return 0

        print()
        print(f"Waiting {interval_seconds} seconds before the next scan...")
        print()
        time.sleep(interval_seconds)


def start_background_monitoring(service: HIDSService, interval_seconds: int) -> threading.Thread:
    def runner() -> None:
        while True:
            try:
                service.run_scan()
            except Exception as exc:  # pragma: no cover
                print(f"Background scan failed: {exc}", file=sys.stderr)
            time.sleep(interval_seconds)

    thread = threading.Thread(target=runner, name="hids-monitor", daemon=True)
    thread.start()
    return thread


LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def warn_if_api_exposed(host: str) -> None:
    if host in LOOPBACK_HOSTS:
        return
    print(
        f"Warning: the API has no authentication and is binding to {host}, so anyone who can "
        "reach this host can read your alerts, including full executable paths and command lines. "
        "Bind 127.0.0.1 unless you have put the API behind your own authenticated proxy.",
        file=sys.stderr,
    )


def serve_api(service: HIDSService, config: HIDSConfig) -> int:
    warn_if_api_exposed(config.api.host)
    start_background_monitoring(service, config.runtime.interval_seconds)
    app = create_app(service)

    if waitress_serve is not None:
        waitress_serve(app, host=config.api.host, port=config.api.port)
        return 0

    print("Waitress is not installed. Falling back to Flask's built-in server.", file=sys.stderr)
    app.run(host=config.api.host, port=config.api.port, debug=False, use_reloader=False)
    return 0


def handle_windows_service_commands(args: argparse.Namespace) -> int | None:
    if args.service_install:
        print(
            install_windows_service(
                config_path=Path(args.config),
                startup=args.service_startup,
                start_immediately=args.service_install_start,
            )
        )
        return 0
    if args.service_remove:
        print(remove_windows_service())
        return 0
    if args.service_start:
        print(start_windows_service())
        return 0
    if args.service_stop:
        print(stop_windows_service())
        return 0
    if args.service_status:
        print(f"Windows Service '{DEFAULT_SERVICE_NAME}' status: {get_windows_service_status()}")
        return 0
    return None


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.iterations < 0:
        parser.error("--iterations cannot be negative.")
    if args.interval is not None and args.interval < 1:
        parser.error("--interval must be at least 1 second.")
    if args.threshold is not None and args.threshold < 1:
        parser.error("--threshold must be at least 1.")
    if args.api_port is not None and args.api_port < 1:
        parser.error("--api-port must be a positive integer.")
    if args.history_limit is not None and args.history_limit < 1:
        parser.error("--history-limit must be at least 1.")
    if args.service_install_start and not args.service_install:
        parser.error("--service-install-start can only be used with --service-install.")
    if args.terminal and args.watch:
        parser.error("--terminal already provides guided monitoring. Remove --watch.")
    if args.terminal and args.serve_api:
        parser.error("--terminal cannot be combined with --serve-api.")
    if args.terminal and args.share_report is not None:
        parser.error("--share-report cannot be combined with --terminal.")
    if args.share_report is not None and args.watch:
        parser.error("--share-report cannot be combined with --watch.")
    if args.share_report is not None and args.serve_api:
        parser.error("--share-report cannot be combined with --serve-api.")

    try:
        service_result = handle_windows_service_commands(args)
    except Exception as exc:
        print(f"Windows Service command failed: {exc}", file=sys.stderr)
        return 1
    if service_result is not None:
        return service_result

    config_path = Path(args.config)
    if not config_path.exists():
        print(
            f"Config file not found: {config_path.resolve()}. Continuing with built-in defaults.",
            file=sys.stderr,
        )
    config = load_config(config_path)
    config = apply_cli_overrides(config, args)
    color_enabled = supports_color(args.no_color)

    service = build_monitoring_service(config)

    if args.terminal:
        return run_terminal(
            service,
            config,
            args,
            color_enabled=color_enabled,
            run_loop_fn=run_loop,
            print_scan_result_fn=print_scan_result,
        )

    if args.share_report is not None:
        print("Running a fresh scan before creating the safe share report...")
        service.run_scan()
        destination = None if args.share_report == "auto" else Path(_resolve_optional_path(args.share_report))
        report_path = service.write_safe_share_report(destination)
        print(f"Safe share report created: {report_path}")
        print("Sensitive details were redacted: local IPs, raw remote IPs, full paths, and full command lines.")
        print("Review the Markdown file once before sharing it outside your team.")
        return 0

    if config.api.enabled:
        return serve_api(service, config)

    if args.watch:
        return run_loop(
            service,
            config.runtime.interval_seconds,
            args.iterations,
            color_enabled=color_enabled,
        )

    log_result = service.run_scan()
    print_scan_result(service, log_result, color_enabled=color_enabled)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
