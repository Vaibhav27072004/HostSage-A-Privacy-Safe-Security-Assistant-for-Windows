# HostSage: A Privacy-Safe Security Assistant for Windows

This project is a lightweight, Windows-friendly Host-Based Intrusion Detection System (HIDS) built with Python. It watches live network connections on your machine, maps them to the process that opened them, and raises alerts when behavior looks suspicious.

The goal is simple: help users notice unusual outbound activity early, investigate it faster, and keep systems safer without needing a large enterprise security stack.

## Quick Start

```powershell
pip install -r requirements.txt
python -m hids --terminal
```

Most useful commands:

- `hostsage --terminal` after installation
- `python -m hids --terminal` for the guided terminal
- `python -m hids` for a one-time scan
- `python -m hids --share-report` for a privacy-safe Markdown report
- `python -m hids --watch --interval 5 --iterations 0` for continuous monitoring

## Important Privacy Notice

> Important: Before sharing this project, its exported results, or any copied log/database files with another person, clear all locally generated monitoring data first.
>
> Generated files such as alert logs, scan history logs, SQLite history databases, and detector state files may contain system-specific information from your machine.
>
> Before sharing, remove or clear files in `logs/`, including JSONL exports, SQLite database files, fallback database files, and saved detection state.
>
> The repository `.gitignore` excludes generated files under `logs/` by default, but `.gitignore` is not retroactive. If any sensitive log files were committed earlier, remove them from Git tracking and history separately before publishing.

## Git Safety for Logs

This project creates runtime files inside `logs/`. These files may contain sensitive user or machine data, so they should not be uploaded to GitHub.

The repository now protects that folder with this `.gitignore` rule:

```gitignore
logs/*
!logs/.gitkeep
```

What this means:

- every generated file inside `logs/` is ignored by Git
- the small `logs/.gitkeep` file is allowed so the folder can stay in the project
- future log files, JSON exports, state files, and SQLite databases should not be included in normal commits

Important note:

- `.gitignore` only protects future tracking
- if `logs/` files were already added to Git earlier, they must be removed from tracking once

If that happens, use:

```powershell
git rm --cached -r logs
git add .gitignore logs/.gitkeep
git commit -m "Stop tracking generated logs"
```

Before pushing, it is a good habit to review staged files with:

```powershell
git status
```

## Before You Push to GitHub

Use this quick checklist before publishing the repository:

- confirm that `logs/` does not contain tracked runtime data
- review `git status`
- make sure API keys are not stored in a committed config file
- keep `config.example.json` as the shareable template, and keep any personal config file private
- if needed, generate a safe share report instead of sharing raw logs or databases

## What This Project Does

The detector collects active network connections, checks which process owns each connection, and applies a set of security-focused rules. It can also enrich suspicious public IP addresses with optional threat intelligence from AbuseIPDB or VirusTotal.

This makes the project useful for:

- students learning cybersecurity and network monitoring
- developers who want visibility into what their machine is connecting to
- lab environments and security demos
- lightweight endpoint monitoring on Windows systems

## What Makes This Project Different

Many HIDS-style student tools stop at raw alerts. This project goes further by focusing on usability and safer collaboration:

- a guided terminal for non-expert users
- persistent history through JSONL logs and SQLite
- Windows Service support for always-on monitoring
- privacy-safe Markdown reporting for sharing findings without exposing raw machine details
- plain-language alert explanations to help users understand what happened and what to check next

## How It Helps Keep Systems Safe

This tool does not replace a firewall, antivirus, or a full SOC platform, but it improves safety by giving you faster visibility into risky behavior such as:

- suspicious ports often used by attacker tools or reverse shells
- unusual outbound spikes from a single process
- one process contacting many different public IP addresses
- repeated connection timing patterns that may look like beaconing
- connections to public IPs that have poor reputation scores

In practice, that means you can detect strange network activity earlier, review which process caused it, and respond before a small issue becomes a bigger incident.

## Key Features

- Real-time connection monitoring using `psutil`
- Automatic fallback to `netstat` when direct collection is limited
- Process-aware alerts with PID, process name, executable path, and command line
- Persistent beacon-detection state across restarts
- Trusted IP/CIDR allowlist support from JSON config and external files
- Detection for suspicious ports, risky process names, and suspicious command-line patterns
- High-frequency outbound connection detection
- Unique remote IP fan-out detection
- Periodic beacon-style behavior detection across scans
- Optional AbuseIPDB and VirusTotal IP reputation checks
- JSONL alert exports plus full scan history logging
- SQLite-backed scan and alert history for durable querying
- HTTP API for health, alerts, summaries, recent scan history, and historical alert views
- Windows Service support for install/start/stop/status on production Windows hosts
- Guided terminal mode for beginner-friendly scanning, monitoring, and alert review
- Privacy-safe Markdown report export with redacted machine details and plain-language alert explanations
- Package entrypoint support with `python -m hids` or an installed CLI command
- Configurable thresholds, persistence, and runtime behavior through JSON config and environment variables

## Detection Rules

The system currently looks for:

- `suspicious_port`: flags traffic using configured high-risk ports such as `1337`, `4444`, `5555`, and `6666`
- `suspicious_process`: flags processes whose name or executable path matches risky tooling such as `nc.exe`, `ncat.exe`, `psexec.exe`, or `socat.exe`
- `suspicious_command_line`: flags encoded or attacker-style command lines such as PowerShell encoded-command usage
- `high_frequency_outbound`: flags a process that creates too many outbound connections in one scan window
- `process_many_unique_ips`: flags a process that reaches many different public IPs
- `periodic_beacon`: flags repeated reconnection behavior that appears regular over time
- `medium_risk_ip` and `high_risk_ip`: flags remote IPs with suspicious reputation scores from enabled threat-intel providers

## Project Structure

```text
attack_detector.py
config.example.json
requirements.txt
pyproject.toml
hids/
  api.py
  cli.py
  collector.py
  config.py
  detector.py
  intel.py
  logger.py
  models.py
  __main__.py
  parser.py
  reporting.py
  runtime.py
  service.py
  state.py
  storage.py
  terminal_ui.py
  windows_service.py
tests/
  test_attack_detector.py
  test_cli.py
  test_config.py
  test_detector.py
  test_logger.py
  test_parser.py
  test_reporting.py
  test_service.py
  test_state.py
  test_windows_service.py
PROJECT_REPORT.md
```

## Installation

1. Make sure Python 3.11 or newer is installed on your Windows machine.
2. Install the project dependencies:

```powershell
pip install -r requirements.txt
```

3. Optional but recommended: install the package itself so you can run the CLI command directly:

```powershell
pip install .
```

After installation, you can also use:

```powershell
hostsage --terminal
```

4. Windows Service mode requires the package to be installed into the Python environment so `pythonservice.exe` can import `hids` at boot.

## Configuration

The default configuration lives in `config.example.json`.

If you want your own settings, create a copy and pass it with `--config`:

```powershell
Copy-Item config.example.json config.json
```

Important configuration options:

- `rules.suspicious_ports`: ports that should be flagged immediately
- `rules.suspicious_process_names`: process names or keywords to treat as suspicious
- `rules.suspicious_command_line_patterns`: encoded or attacker-style command-line substrings to flag
- `rules.known_networks`: trusted public IPs or CIDR ranges to allow
- `rules.known_network_files`: external files containing trusted IPs or CIDR ranges
- `rules.outbound_connection_threshold`: alert when one process opens too many outbound connections
- `rules.unique_ip_threshold`: alert when one process contacts too many unique public IPs
- `rules.beacon_min_samples`: minimum repeated events before beacon checks run
- `rules.beacon_jitter_seconds`: timing tolerance for beacon detection
- `threat_intel.abuseipdb_api_key`: optional API key for AbuseIPDB
- `threat_intel.virustotal_api_key`: optional API key for VirusTotal
- `runtime.interval_seconds`: scan interval for watch mode
- `runtime.export_path`: file or folder for JSONL alert exports
- `runtime.scan_log_path`: JSONL file for full scan history
- `runtime.database_path`: SQLite database for durable scan and alert history
- `runtime.state_path`: persistent state file used for repeated-behavior detection
- `runtime.history_limit`: number of recent scans kept in memory for the API
- `api.host` and `api.port`: API bind settings

Supported environment overrides:

- `HIDS_ABUSEIPDB_API_KEY`
- `HIDS_VIRUSTOTAL_API_KEY`
- `HIDS_INTERVAL_SECONDS`
- `HIDS_EXPORT_PATH`
- `HIDS_SCAN_LOG_PATH`
- `HIDS_DATABASE_PATH`
- `HIDS_STATE_PATH`
- `HIDS_HISTORY_LIMIT`
- `HIDS_API_HOST`
- `HIDS_API_PORT`

## How To Use It

### 1. Open the guided terminal

```powershell
python -m hids --terminal
```

This launches a user-friendly terminal menu for running scans, starting monitoring, checking recent alerts, generating a privacy-safe share report, and reviewing storage/configuration details.

Current terminal options include:

- run a quick scan now
- start guided monitoring
- review recent alerts with explanations
- review recent scans
- create a safe share report
- view configuration and storage
- show helpful commands

### 2. Run a single scan

```powershell
python -m hids
```

This scans current connections and prints a summary of any alerts.

If you want to use the legacy wrapper script, this still works too:

```powershell
python attack_detector.py
```

### 2a. Create a privacy-safe share report

```powershell
python -m hids --share-report
```

This runs a fresh scan and writes a Markdown report with:

- plain-language explanations for each alert
- redacted local IPs and remote IPs using aliases such as `local-host-1` and `remote-host-1`
- redacted full file paths and command lines
- recent trend and recurring-pattern summaries

You can also choose your own output path:

```powershell
python -m hids --share-report logs\incident_report.md
```

### 3. Monitor continuously

```powershell
python -m hids --watch --interval 5 --iterations 0
```

This keeps scanning every 5 seconds until you stop it.

### 4. Use a custom config file

```powershell
python -m hids --config config.json
```

### 5. Change the outbound alert threshold

```powershell
python -m hids --threshold 15
```

### 6. Export structured alerts

```powershell
python -m hids --export logs
```

This writes alert JSONL files. The upgraded project also keeps a continuous scan history log using `runtime.scan_log_path` and a queryable SQLite history database using `runtime.database_path`.

### 6a. Override the SQLite history database location

```powershell
python -m hids --database logs\custom_history.db
```

If the configured SQLite file is locked or unusable, the project automatically falls back to a sibling `*_fallback.db` file so historical storage keeps working.

> Important: Clear all exported logs and database files before sending project outputs to another person.

### 7. Start the optional API

```powershell
python -m hids --serve-api
```

Available endpoints:

- `GET /health`
- `GET /summary`
- `GET /alerts`
- `GET /explained-alerts`
- `GET /history`
- `GET /alert-history`
- `GET /explained-alert-history`
- `GET /alert-groups`
- `GET /safe-share-report`

When `waitress` is installed, the API is served with Waitress instead of Flask's development server.

### 8. Use an external allowlist file

```powershell
python -m hids --known-ips-file known_ips.example.txt
```

This is useful when you want trusted public IPs managed separately from the main JSON config.

### 9. Install as a Windows Service

Install the service:

```powershell
python -m hids --service-install --config config.example.json --service-startup auto
```

Install and start it immediately:

```powershell
python -m hids --service-install --config config.example.json --service-install-start
```

Check service status:

```powershell
python -m hids --service-status
```

Start or stop the service later:

```powershell
python -m hids --service-start
python -m hids --service-stop
```

Remove the service:

```powershell
python -m hids --service-remove
```

Notes:

- The Windows Service uses the config file path stored at install time.
- Service mode focuses on continuous monitoring and log generation.
- If `api.enabled` is set in the config, the service keeps monitoring but does not host the HTTP API.

## Example Output

```text
==============================================================================
HostSage Scan Summary
==============================================================================
Status: ATTENTION NEEDED
Timestamp     : 2026-04-07T03:05:15+00:00
Collector     : psutil
Scan duration : 115 ms
Connections   : 77
Public IPs    : 11
Alerts        : 2
Risk mix      : HIGH:2

Top Alerts
------------------
 1. [HIGH] suspicious port          python.exe (PID 1234)        -> 185.234.217.12:4444 | score 70
    why: Ports such as 4444 or 5555 are often used by reverse shells, tunnels, or unauthorized remote tools.
    next: Confirm whether this process is expected to use the reported port.
 2. [HIGH] suspicious command line  powershell.exe (PID 4321)    -> 104.16.0.1:443      | score 82
    why: Encoded or downloader-style command lines are frequently used to hide behavior or fetch follow-on payloads.
    next: Review the parent process and execution context for the command.

Saved Output
------------------
Alert log      : logs\alerts_20260407_030515.jsonl
Scan history   : logs\scans.jsonl
SQLite history : logs\hids_history.db
```

## Example Safe Share Report

```text
# HostSage Safe Share Report

Generated at: 2026-04-07T05:46:29+00:00

This report is designed for safer sharing. Raw local IPs, raw remote IPs, full file paths, and full command lines are replaced with aliases or summaries.

## Executive Summary

- Latest scan timestamp: 2026-04-07T05:46:29+00:00
- Alerts in latest scan: 1
- Top alert themes: suspicious port (1)

## Key Findings

### Finding 1: Connection used a high-risk port

- Severity: HIGH (score 82)
- Detection rule: `suspicious_port`
- Observed process: python.exe (PID 4242)
- Local endpoint alias: local-host-1:55000
- Remote endpoint alias: remote-host-1:4444
- Process path: <redacted-path>/python.exe
- Command line: Redacted command line for python.exe (4 tokens hidden)
```

## Running Tests

```powershell
python -m unittest discover -s tests -v
```

## Limitations

- This tool is heuristic-based, so false positives are possible.
- It is designed for defensive monitoring and investigation, not automatic blocking.
- It does not inspect encrypted payload contents.
- It should be used alongside firewalls, antivirus, patching, and other security controls.

## Summary

This project helps make systems safer by turning raw network activity into readable security alerts. Instead of manually checking connections and guessing what is normal, users can quickly spot suspicious behavior, identify the responsible process, and investigate with better context.
