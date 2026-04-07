from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from hids.models import Alert, ScanResult


@dataclass(frozen=True)
class AlertGuidance:
    title: str
    why_it_matters: str
    next_steps: tuple[str, ...]
    false_positive_hint: str


ALERT_GUIDANCE: dict[str, AlertGuidance] = {
    "suspicious_port": AlertGuidance(
        title="Connection used a high-risk port",
        why_it_matters="Ports such as 4444 or 5555 are often used by reverse shells, tunnels, or unauthorized remote tools.",
        next_steps=(
            "Confirm whether this process is expected to use the reported port.",
            "Check whether the remote host belongs to a trusted service or team system.",
            "Review recent software installs or scripts that launched the process.",
        ),
        false_positive_hint="Developer tools, lab exercises, and legitimate remote-admin utilities can trigger this rule.",
    ),
    "suspicious_process": AlertGuidance(
        title="Process name matched a risky tool pattern",
        why_it_matters="Netcat-style tools and remote execution utilities are common in incident response, labs, and attacker workflows.",
        next_steps=(
            "Verify who launched the process and why it is present on the host.",
            "Check the file publisher and installation source for the executable.",
            "Look for matching scheduled tasks, scripts, or remote access sessions.",
        ),
        false_positive_hint="Security engineers and administrators may legitimately use these tools during maintenance or testing.",
    ),
    "suspicious_command_line": AlertGuidance(
        title="Command line contained a suspicious pattern",
        why_it_matters="Encoded or downloader-style command lines are frequently used to hide behavior or fetch follow-on payloads.",
        next_steps=(
            "Review the parent process and execution context for the command.",
            "Check whether the command was launched by automation, a user action, or a scheduled task.",
            "If available, compare the command to a known-good script or deployment job.",
        ),
        false_positive_hint="Administrative scripts and packaging tools sometimes use encoded or web-downloading arguments legitimately.",
    ),
    "high_frequency_outbound": AlertGuidance(
        title="Process created many outbound connections in one scan window",
        why_it_matters="Sudden spikes in outbound traffic can indicate scanning, exfiltration, update storms, or a misbehaving client.",
        next_steps=(
            "Check whether the process recently updated, synchronized, or retried failed network requests.",
            "Review destination diversity to see whether traffic is focused or broad.",
            "Investigate whether the timing lines up with user activity or a background task.",
        ),
        false_positive_hint="Browsers, package managers, cloud sync tools, and update agents can create short-lived connection bursts.",
    ),
    "process_many_unique_ips": AlertGuidance(
        title="Process contacted many unique external hosts",
        why_it_matters="High fan-out behavior can be normal for browsers or CDNs, but it can also indicate scanning, scraping, or beacon distribution.",
        next_steps=(
            "Decide whether the process normally talks to many cloud endpoints.",
            "Check DNS, proxy, or application logs for the related destinations.",
            "Compare the behavior to a known-good baseline for that application.",
        ),
        false_positive_hint="Browsers, content delivery clients, and security tools often contact many IPs during normal use.",
    ),
    "periodic_beacon": AlertGuidance(
        title="Repeated network timing resembled beaconing",
        why_it_matters="Regular reconnect intervals are a common trait of command-and-control check-ins and some automated agents.",
        next_steps=(
            "Review how long the pattern has been happening and whether it matches an expected agent heartbeat.",
            "Check the destination owner and any security tooling that might use scheduled polling.",
            "Investigate persistence mechanisms if the process is unexpected.",
        ),
        false_positive_hint="Monitoring agents, endpoint management tools, and chat clients can produce very regular network intervals.",
    ),
    "high_risk_ip": AlertGuidance(
        title="Remote host had a high threat-intelligence score",
        why_it_matters="External reputation systems linked the destination to suspicious or malicious activity.",
        next_steps=(
            "Validate whether the destination belongs to a trusted vendor or service.",
            "Review any matching alerts from firewall, proxy, or DNS tooling.",
            "Consider isolating the process or host if other indicators support malicious activity.",
        ),
        false_positive_hint="Threat-intelligence feeds can be noisy, stale, or context-dependent.",
    ),
    "medium_risk_ip": AlertGuidance(
        title="Remote host had a moderate threat-intelligence score",
        why_it_matters="The destination has some suspicious history and deserves review, especially if other alerts point to the same host.",
        next_steps=(
            "Correlate this destination with other alerts from the same process or host.",
            "Check whether the connection was user-initiated or background activity.",
            "Monitor for repeated contact with the same destination over time.",
        ),
        false_positive_hint="Shared hosting, VPN endpoints, and recycled IPs can inherit moderate reputation scores without being malicious now.",
    ),
}


def get_alert_guidance(reason: str) -> AlertGuidance:
    return ALERT_GUIDANCE.get(
        reason,
        AlertGuidance(
            title=_humanize_reason(reason).title(),
            why_it_matters="This alert matched one of the configured detection rules.",
            next_steps=("Review the process and destination in your environment.",),
            false_positive_hint="Context from the host and user activity is needed to judge this alert.",
        ),
    )


def _basename(path_value: str) -> str:
    cleaned = (path_value or "").strip().strip('"').rstrip("\\/")
    if not cleaned:
        return ""
    windows_name = PureWindowsPath(cleaned).name
    if windows_name:
        return windows_name
    posix_name = PurePosixPath(cleaned).name
    return posix_name or cleaned


def _humanize_reason(reason: str) -> str:
    return reason.replace("_", " ")


def _iso_timestamp(moment: datetime | None = None) -> str:
    return (moment or datetime.now(timezone.utc)).isoformat(timespec="seconds")


class AliasBook:
    def __init__(self) -> None:
        self._local_hosts: dict[str, str] = {}
        self._remote_hosts: dict[str, str] = {}

    def local_host(self, raw_value: str | None) -> str:
        return self._assign(self._local_hosts, raw_value, "local-host")

    def remote_host(self, raw_value: str | None) -> str:
        return self._assign(self._remote_hosts, raw_value, "remote-host")

    @staticmethod
    def _assign(bucket: dict[str, str], raw_value: str | None, prefix: str) -> str:
        cleaned = (raw_value or "").strip()
        if not cleaned:
            return "-"
        alias = bucket.get(cleaned)
        if alias is None:
            alias = f"{prefix}-{len(bucket) + 1}"
            bucket[cleaned] = alias
        return alias


def _sanitize_process_path(path_value: str) -> str:
    name = _basename(path_value)
    return f"<redacted-path>/{name}" if name else "Not available"


def _sanitize_command_line(command_line: str) -> str:
    raw = (command_line or "").strip()
    if not raw:
        return "Not available"
    executable = _basename(raw.split()[0])
    token_count = len(raw.split())
    if executable:
        return f"Redacted command line for {executable} ({token_count} tokens hidden)"
    return f"Redacted command line ({token_count} tokens hidden)"


def _format_endpoint(alias: str, port: int | None) -> str:
    return alias if port is None or alias == "-" else f"{alias}:{port}"


def _normalize_alert_payload(alert: Alert | dict[str, Any]) -> dict[str, Any]:
    return alert.to_dict() if isinstance(alert, Alert) else dict(alert)


def _build_reason_counter(latest_result: ScanResult | None, alert_history: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for alert in alert_history:
        counter[_humanize_reason(str(alert.get("detection_reason", "unknown")))] += 1
    if not counter and latest_result is not None:
        for alert in latest_result.alerts:
            counter[_humanize_reason(alert.detection_reason)] += 1
    return counter


def _metadata_lines(metadata: dict[str, Any], aliases: AliasBook) -> list[str]:
    lines: list[str] = []
    if "matched_port" in metadata:
        lines.append(f"Matched port: {metadata['matched_port']}")
    if "matched_pattern" in metadata:
        lines.append(f"Matched command-line pattern: {metadata['matched_pattern']}")
    if "connection_count" in metadata:
        lines.append(f"Observed connection count in scan window: {metadata['connection_count']}")
    if "unique_ip_count" in metadata:
        lines.append(f"Observed unique remote hosts in scan window: {metadata['unique_ip_count']}")
    if "sample_ips" in metadata and isinstance(metadata["sample_ips"], list):
        samples = [aliases.remote_host(str(item)) for item in metadata["sample_ips"][:5]]
        lines.append(f"Sample remote host aliases: {', '.join(samples)}")
    if "intervals_seconds" in metadata and isinstance(metadata["intervals_seconds"], list):
        intervals = ", ".join(str(item) for item in metadata["intervals_seconds"][:6])
        lines.append(f"Observed intervals in seconds: {intervals}")
    return lines


def _severity_summary(risk_label: str, risk_score: int) -> str:
    normalized = risk_label.upper()
    if normalized == "HIGH":
        prefix = "High severity. Review this activity as soon as possible."
    elif normalized == "MEDIUM":
        prefix = "Medium severity. This behavior deserves investigation, especially if repeated."
    else:
        prefix = "Low severity. This may be benign, but it is still worth validating."
    return f"{prefix} Risk score: {risk_score}."


def build_explained_alert(
    alert: Alert | dict[str, Any],
    *,
    redact_sensitive: bool = False,
    aliases: AliasBook | None = None,
) -> dict[str, Any]:
    payload = _normalize_alert_payload(alert)
    guidance = get_alert_guidance(str(payload.get("detection_reason", "unknown")))
    metadata = dict(payload.get("metadata", {}))
    alias_book = aliases or AliasBook()

    explained: dict[str, Any] = {
        **payload,
        "reason_display": _humanize_reason(str(payload.get("detection_reason", "unknown"))),
        "explanation_title": guidance.title,
        "why_flagged": guidance.why_it_matters,
        "severity_summary": _severity_summary(
            str(payload.get("risk_label", "LOW")),
            int(payload.get("risk_score", 0)),
        ),
        "recommended_next_steps": list(guidance.next_steps),
        "false_positive_hint": guidance.false_positive_hint,
        "evidence_summary": _metadata_lines(metadata, alias_book),
    }

    if redact_sensitive:
        explained.update(
            {
                "redacted_local_endpoint": _format_endpoint(
                    alias_book.local_host(str(payload.get("local_ip", "")) or None),
                    payload.get("local_port") if isinstance(payload.get("local_port"), int) else None,
                ),
                "redacted_remote_endpoint": _format_endpoint(
                    alias_book.remote_host(str(payload.get("remote_ip", "")) or None),
                    payload.get("remote_port") if isinstance(payload.get("remote_port"), int) else None,
                ),
                "redacted_process_path": _sanitize_process_path(str(payload.get("process_path", ""))),
                "redacted_command_line": _sanitize_command_line(str(payload.get("process_command_line", ""))),
            }
        )

    return explained


def _finding_lines(index: int, alert: dict[str, Any], aliases: AliasBook) -> list[str]:
    explained = build_explained_alert(alert, redact_sensitive=True, aliases=aliases)
    reason = str(explained.get("detection_reason", "unknown"))
    process_name = str(explained.get("process_name", "Unknown"))
    pid = explained.get("pid", "-")
    intel_provider = str(explained.get("intel_provider", "")) or "not configured"
    intel_summary = str(explained.get("intel_summary", "")) or "No threat-intelligence summary available."

    lines = [
        f"### Finding {index}: {explained['explanation_title']}",
        "",
        f"- Severity: {str(explained.get('risk_label', 'LOW')).upper()} (score {explained.get('risk_score', 0)})",
        f"- Detection rule: `{reason}`",
        f"- Why it matters: {explained['why_flagged']}",
        f"- Observed process: {process_name} (PID {pid})",
        f"- Local endpoint alias: {explained['redacted_local_endpoint']}",
        f"- Remote endpoint alias: {explained['redacted_remote_endpoint']}",
        f"- Process path: {explained['redacted_process_path']}",
        f"- Command line: {explained['redacted_command_line']}",
        f"- Threat intelligence: {intel_provider} | {intel_summary}",
    ]
    evidence = list(explained.get("evidence_summary", []))
    if evidence:
        lines.append("- Evidence summary:")
        lines.extend(f"  - {item}" for item in evidence)
    lines.append("- Recommended next steps:")
    lines.extend(f"  - {step}" for step in explained.get("recommended_next_steps", []))
    lines.append(f"- False-positive note: {explained['false_positive_hint']}")
    lines.append("")
    return lines


def _recurring_pattern_lines(alert_groups: list[dict[str, Any]], aliases: AliasBook) -> list[str]:
    if not alert_groups:
        return ["No recurring alert patterns were available in recent history.", ""]

    lines: list[str] = []
    for group in alert_groups:
        remote_alias = aliases.remote_host(str(group.get("remote_ip", "")) or None)
        remote_endpoint = _format_endpoint(
            remote_alias,
            group.get("remote_port") if isinstance(group.get("remote_port"), int) else None,
        )
        lines.append(
            "- "
            f"{_humanize_reason(str(group.get('detection_reason', 'unknown')))} | "
            f"process={group.get('process_name', 'Unknown')} | "
            f"severity={str(group.get('risk_label', 'LOW')).upper()} | "
            f"occurrences={group.get('occurrence_count', 0)} | "
            f"remote={remote_endpoint} | "
            f"first_seen={group.get('first_seen', '-')} | "
            f"last_seen={group.get('last_seen', '-')}"
        )
    lines.append("")
    return lines


def _recent_scan_lines(recent_scans: list[dict[str, Any]]) -> list[str]:
    if not recent_scans:
        return ["No recent scan history was available.", ""]

    lines: list[str] = []
    for scan in recent_scans:
        alert_count = scan.get("alert_count", len(scan.get("alerts", [])))
        lines.append(
            "- "
            f"{scan.get('timestamp', '-')} | "
            f"alerts={alert_count} | "
            f"connections={scan.get('connection_count', 0)} | "
            f"public_ips={scan.get('public_remote_ip_count', 0)} | "
            f"duration={scan.get('scan_duration_ms', 0)} ms | "
            f"source={scan.get('collector_source', 'unknown')}"
        )
    lines.append("")
    return lines


def default_safe_share_report_path(base_dir: Path | None = None, *, generated_at: datetime | None = None) -> Path:
    timestamp = (generated_at or datetime.now(timezone.utc)).strftime("%Y%m%d_%H%M%S")
    destination_dir = base_dir or (Path.cwd() / "logs")
    return destination_dir / f"safe_share_report_{timestamp}.md"


def build_safe_share_report(
    latest_result: ScanResult | None,
    summary: dict[str, Any],
    alert_history: list[dict[str, Any]],
    recent_scans: list[dict[str, Any]],
    alert_groups: list[dict[str, Any]],
    *,
    generated_at: datetime | None = None,
    max_findings: int = 5,
) -> str:
    aliases = AliasBook()
    generated_timestamp = _iso_timestamp(generated_at)
    reason_counter = _build_reason_counter(latest_result, alert_history)
    top_reasons = ", ".join(f"{reason} ({count})" for reason, count in reason_counter.most_common(3)) or "none"

    if latest_result is not None and latest_result.alerts:
        finding_alerts = [_normalize_alert_payload(alert) for alert in latest_result.alerts[:max_findings]]
    else:
        finding_alerts = [_normalize_alert_payload(alert) for alert in alert_history[:max_findings]]

    lines = [
        "# HostSage Safe Share Report",
        "",
        f"Generated at: {generated_timestamp}",
        "",
        "This report is designed for safer sharing. Raw local IPs, raw remote IPs, full file paths, and full command lines are replaced with aliases or summaries.",
        "",
        "## Executive Summary",
        "",
        f"- Latest scan timestamp: {summary.get('timestamp') or 'No in-memory scan available'}",
        f"- Latest collector source: {summary.get('collector_source', 'unknown')}",
        f"- Alerts in latest scan: {summary.get('alert_count', 0)}",
        f"- Warnings in latest scan: {summary.get('warning_count', 0)}",
        f"- Recent alerts reviewed: {len(alert_history)}",
        f"- Recent scan records reviewed: {len(recent_scans)}",
        f"- Recurring alert groups reviewed: {len(alert_groups)}",
        f"- Top alert themes: {top_reasons}",
        "",
        "## Privacy Notes",
        "",
        "- `local-host-*` aliases represent redacted local or private addresses.",
        "- `remote-host-*` aliases represent redacted remote destinations.",
        "- Full executable paths are reduced to filename-only summaries.",
        "- Full command lines are replaced with short privacy-safe descriptions.",
        "",
        "## Latest Scan Snapshot",
        "",
        f"- Status: {summary.get('status', 'unknown')}",
        f"- Connections inspected: {summary.get('connection_count', 0)}",
        f"- Public remote IPs observed: {summary.get('public_remote_ip_count', 0)}",
        f"- Scan duration: {summary.get('scan_duration_ms', 0)} ms",
        f"- Storage backend: {summary.get('storage', {}).get('backend', 'disabled')}",
        f"- Stored scans: {summary.get('storage', {}).get('scan_count', 0)}",
        f"- Stored alerts: {summary.get('storage', {}).get('alert_count', 0)}",
        "",
        "## Key Findings",
        "",
    ]

    if finding_alerts:
        for index, alert in enumerate(finding_alerts, start=1):
            lines.extend(_finding_lines(index, alert, aliases))
    else:
        lines.extend(
            [
                "No alerts were available for the selected report window.",
                "",
            ]
        )

    lines.extend(
        [
            "## Recurring Patterns",
            "",
        ]
    )
    lines.extend(_recurring_pattern_lines(alert_groups, aliases))
    lines.extend(
        [
            "## Recent Scan Trend",
            "",
        ]
    )
    lines.extend(_recent_scan_lines(recent_scans))
    lines.extend(
        [
            "## Sharing Guidance",
            "",
            "- Review the report once before sending it outside your team.",
            "- If you need to share raw indicators privately, send them through a secure channel instead of editing this report.",
            "- If an alert looks urgent, pair this report with host, firewall, or EDR logs for deeper investigation.",
            "",
        ]
    )

    return "\n".join(lines).strip() + "\n"
