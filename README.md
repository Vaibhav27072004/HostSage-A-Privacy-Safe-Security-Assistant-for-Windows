# HostSage: A Privacy-Safe Security Assistant for Windows

**A lightweight Windows host intrusion detector that tells you which process opened a connection, explains why it matters in plain language, and lets you share the finding without leaking your machine's details.**

Built with Python and `psutil`. No agent fleet, no licence, no SOC required.

## The Problem This Solves

Right now your computer has dozens of open network connections. Try to answer three questions about them:

1. **Which program opened each one?** Windows will show you the connections with `netstat -ano`, but only as numbers. Mapping a PID to a program, its install path, and the command line that launched it is a separate manual lookup for every single row.
2. **Is any of it unusual?** A connection to port 4444, one process talking to forty different hosts, or a reconnect every thirty seconds like clockwork. These are ordinary-looking rows in a table, and obvious signals once something tells you what to look for.
3. **Can you ask someone for help?** The moment you paste your logs into a chat or an issue tracker, you have also handed over your usernames, your internal IP addresses, your folder layout, and whatever secrets were sitting in a command line.

Enterprise tooling answers all three. It also costs money, needs infrastructure, and assumes someone on staff already speaks fluent security. For a student, a solo developer, or a small team with no security budget, the practical options are "install a heavyweight agent" or "hope nothing is wrong."

HostSage is built for that gap. One command, a readable answer, and a report you can safely send to someone else.

```text
 1. [HIGH] suspicious port          python.exe (PID 1234)        -> 185.234.217.12:4444 | score 70
    why: Ports such as 4444 or 5555 are often used by reverse shells, tunnels, or unauthorized remote tools.
    next: Confirm whether this process is expected to use the reported port.
```

That is the whole idea: the process, the destination, the reason, and the next step, in the place where you already are.

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

## Open Source

HostSage is now open source under the MIT License, and contributions are welcome.

If you want to improve this project, you can help with:

- better beginner-friendly alert explanations
- privacy-safe reporting improvements
- bug fixes
- tests
- documentation
- usability improvements for Windows users

Contribution guidance is available in [CONTRIBUTING.md](CONTRIBUTING.md), and the project license is available in [LICENSE](LICENSE).

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

## Who It Helps, and How

**Students learning security.** You get to see command-and-control beaconing, port-based detection, and IP reputation scoring against your own live traffic instead of a canned lab capture, with an explanation of what each rule is actually looking for. Every alert carries a *why it matters* line and a *false positive note*, so the tool teaches while it reports.

**Solo developers and freelancers.** You find out that a dependency's post-install script phones home, or that a tool you installed last week opens a connection every thirty seconds. One command, no agent, no account.

**Small teams with no security budget.** Install it as a Windows Service and it monitors continuously, keeps queryable history in SQLite, and exposes a local HTTP API you can point a dashboard at. When something looks wrong, `--share-report` produces a Markdown writeup you can hand to a contractor or attach to a ticket with the machine details already stripped out.

**Anyone who has to ask for help.** This is the part most tools skip. Raw logs leak usernames, internal addressing, directory structure, and command-line arguments. HostSage redacts all of it into stable aliases, so the behavior stays legible to whoever is helping you while the specifics stay on your machine:

```text
- Severity: HIGH (score 82)
- Detection rule: `suspicious_port`
- Observed process: python.exe (PID 4242)
- Local endpoint alias: local-host-1:55000
- Remote endpoint alias: remote-host-1:4444
- Process path: <redacted-path>/python.exe
- Command line: Redacted command line for python.exe (4 tokens hidden)
```

The token count is kept on purpose. A reviewer can tell there were four arguments without seeing what they were.

## Case Study: Making the Alerts Worth Trusting

A detector that cries wolf is worse than no detector, because people learn to close it. That was not a hypothetical risk for this project. It happened here, and fixing it has been the most valuable work the project has had.

**What went wrong.** On a first run against an ordinary developer laptop, HostSage reported this:

```text
 1. [HIGH] periodic beacon          <desktop app> (PID 22488)   -> <endpoint>:443 | score 85
    why: Regular reconnect intervals are a common trait of command-and-control check-ins.
```

A routine desktop application, scored 85 out of 100, labelled with the signature of malware calling home. On the very first scan, before any timing history could possibly exist.

**The root cause.** Beacon detection tracked history per `(pid, process, remote ip, remote port)`, but decided whether a connection was *new* using a key that also included the local port. An application holding twenty sockets open to one endpoint therefore recorded twenty separate observations, all stamped with the same scan time. The timing check then measured the gaps between them:

```text
intervals_seconds: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, ... ]
```

Zero variance. Mathematically a perfect beacon, which is exactly the wrong conclusion. Any program that keeps several connections open to one server, which is to say every browser, chat client, and sync tool, was guaranteed to trip the highest-severity rule in the project.

**The fix.** Two changes, because there were two distinct faults:

- concurrent sockets to the same endpoint are now recorded as **one observation per scan**, not one per socket
- the timing check **rejects degenerate intervals** outright. Samples closer together than one configurable beacon interval are not check-ins, and a run of identical timestamps can no longer pass a jitter tolerance that it only satisfied because the spread was zero

A related fault sat behind it. The detector saved its beacon timestamps across restarts but not its record of which connections it had already seen, so every restart treated every open socket as brand new and rebuilt the same false pattern from scratch. That state is now persisted too, which matters most in Windows Service mode, where a restart happens on every boot.

**The result.** Verified on the same machine that produced the false positive, across five consecutive runs:

| Measure | Before | After |
| --- | --- | --- |
| Beacon alerts on ordinary traffic | HIGH, score 85 | none |
| Timing samples per endpoint, per scan | up to 20 | 1 |
| Intervals measured | all `0.0` | genuine elapsed time |
| Genuine periodic beaconing still detected | yes | yes |

That last row is the one that matters. The rule was not weakened into silence, it was corrected, so it fires on real periodicity and stays quiet on ordinary software. Regression tests now cover both halves, including the exact case that originally broke.

**What else the review turned up.** Chasing one false positive exposed four more problems worth naming, because each would have cost a user something real:

- **A trusted-IP allowlist that mostly did not work.** `known_networks` was only consulted by the threat-intelligence rules, so adding an address you trusted still left it flagged for suspicious ports, risky process names, and connection volume. The allowlist is now applied once, ahead of every rule.
- **A history database that could delete itself.** On any database error the store removed the file and started over, and `database is locked` is such an error, so the ordinary case of the CLI running alongside the service risked wiping saved history. Locks are now treated as temporary and reported, while genuine corruption moves the unreadable file aside as `*.corrupt-<timestamp>` and keeps it, because on a security tool that history is evidence.
- **Alerts that could name the wrong program.** Process details were cached and never invalidated, so under a long-running service, Windows reusing a PID would eventually attribute a connection to a process that had already exited. The cache is now scoped to a single scan.
- **An unauthenticated API with no warning attached.** It binds to `127.0.0.1` by default, which is correct, but moving it off loopback silently published full executable paths and command lines to the network. That now warns loudly.

**Test coverage** went from 27 tests to 72, closing the three modules that previously had none, with every fix above locked in by a regression test.

The lesson generalises to any detection tool: a rule that produces confident high-severity alerts on normal software does more damage than a rule that does not exist. Being right quietly is the feature.

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
CONTRIBUTING.md
LICENSE
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
- `rules.known_networks`: trusted public IPs or CIDR ranges to allow, applied to every detection rule
- `rules.known_network_files`: external files containing trusted IPs or CIDR ranges
- `rules.outbound_connection_threshold`: alert when one process opens too many outbound connections
- `rules.unique_ip_threshold`: alert when one process contacts too many unique public IPs
- `rules.beacon_min_samples`: minimum repeated events before beacon checks run
- `rules.beacon_jitter_seconds`: timing tolerance for beacon detection
- `rules.beacon_min_interval_seconds`: shortest gap that still counts as a beacon check-in, which keeps processes holding several sockets open to one endpoint from looking periodic
- `threat_intel.abuseipdb_api_key`: optional API key for AbuseIPDB
- `threat_intel.virustotal_api_key`: optional API key for VirusTotal
- `runtime.interval_seconds`: scan interval for watch mode
- `runtime.export_path`: file or folder for JSONL alert exports
- `runtime.scan_log_path`: JSONL file for full scan history
- `runtime.database_path`: SQLite database for durable scan and alert history
- `runtime.state_path`: persistent state file used for repeated-behavior detection
- `runtime.history_limit`: number of recent scans kept in memory for the API
- `api.host` and `api.port`: API bind settings. The API has no authentication, so keep `api.host` on `127.0.0.1` unless you put it behind your own authenticated proxy

Supported environment overrides:

- `HIDS_ABUSEIPDB_API_KEY`
- `HIDS_VIRUSTOTAL_API_KEY`
- `HIDS_INTERVAL_SECONDS`
- `HIDS_EXPORT_PATH`
- `HIDS_SCAN_LOG_PATH`
- `HIDS_DATABASE_PATH`
- `HIDS_STATE_PATH`
- `HIDS_HISTORY_LIMIT`
- `HIDS_STATE_HISTORY_SIZE`
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

How storage handles trouble:

- a locked database is treated as temporary. The scan reports a warning and the next scan writes normally, so history is never split across two files
- an unreadable or corrupted database is moved aside as `*.corrupt-<timestamp>` and a fresh one is started at the configured path. The old file is kept for review rather than deleted
- if the corrupted file can be neither read nor moved aside, the project falls back to a sibling `*_fallback.db` file, and the terminal's configuration screen reports that a fallback is active
- any other write failure, such as a path that cannot be opened at all, is reported as a scan warning rather than hidden, because a sibling file in the same folder would fail the same way

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

## Contributing

Contributions are welcome. If you want to help, start with:

- improving explainable alerts
- strengthening privacy-safe redaction
- adding tests
- improving documentation and terminal usability

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Limitations

- This tool is heuristic-based, so false positives are possible.
- Beacon detection samples one observation per scan, so it cannot resolve timing faster than `runtime.interval_seconds`, and a process that opens a fresh connection to the same destination on every scan can still look regular.
- It is designed for defensive monitoring and investigation, not automatic blocking.
- It does not inspect encrypted payload contents.
- It should be used alongside firewalls, antivirus, patching, and other security controls.

## Summary

HostSage turns a table of numbers into an answer. Instead of reading `netstat` output and guessing what is normal, you get the responsible process, a plain-language reason, a suggested next step, and an honest note about when the alert is likely to be wrong.

Three things it is built to do well:

- **Attribute.** Every connection is tied to the process, path, and command line behind it, because "something is talking to this address" is not actionable on its own.
- **Explain.** Each rule ships with why it matters, what to check next, and when it tends to produce false positives, so the tool is usable by someone who is still learning.
- **Share safely.** Findings leave the machine as aliases and summaries rather than raw logs, so asking for help does not mean publishing your environment.

It is not a firewall, an antivirus, or a SOC platform, and it does not block anything. It is the missing middle step between noticing that something feels off and knowing what to look at.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
