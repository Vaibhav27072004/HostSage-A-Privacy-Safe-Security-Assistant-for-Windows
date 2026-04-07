# Project Report

## HostSage: A Privacy-Safe Security Assistant for Windows

## Important Privacy Note

Before sharing this project or any generated report, remove or review locally saved monitoring data first. Runtime files such as logs, detector state, SQLite history, and exported reports may contain machine-specific information. The project now uses `.gitignore` to keep generated `logs/` data out of normal Git commits, but previously tracked files still need manual cleanup.

## 1. Introduction

Modern systems constantly create outbound and inbound network connections, but most users cannot easily tell which process created a connection, whether that behavior is normal, or whether an alert is serious. Existing enterprise tools are often powerful but expensive, complex, and intimidating for beginners.

This project presents a Windows-friendly Host-Based Intrusion Detection System (HIDS) built with Python. It monitors live host connections, maps traffic to the responsible process, applies security-focused heuristics, and stores useful history for investigation. More importantly, the project is designed to make security easier for normal users through:

- a guided terminal experience
- plain-language alert explanations
- privacy-safe report sharing
- persistent scan and alert history

That design choice is the main direction of the project. Instead of becoming just another rule-based detector, the system becomes a practical security assistant for students, beginners, and small teams.

## 2. Objective

The main objectives of this project are:

- to monitor active network connections in near real time
- to map suspicious behavior back to the responsible process
- to detect risky network patterns such as suspicious ports, encoded commands, high outbound volume, beacon-like timing, and risky public IP reputation
- to provide user-friendly investigation workflows through a terminal interface and structured history
- to allow safer collaboration by generating privacy-safe reports that can be shared without exposing raw machine details

## 3. Problem Statement

Many users are unaware of:

- hidden or unexpected background network activity
- which process owns a suspicious connection
- how serious an alert is
- whether an alert could be a false positive
- how to safely share findings with another person

Typical security tools solve detection but not usability. Beginners often get raw technical output without enough explanation, while report sharing can expose usernames, local IPs, file paths, or sensitive command-line tokens.

This project addresses both problems:

- detection of suspicious host network behavior
- explanation and privacy-safe sharing of findings

## 4. Technologies Used

| Technology | Purpose |
| --- | --- |
| Python | Core programming language |
| PowerShell / CMD | Execution environment on Windows |
| `psutil` | Live connection and process collection |
| `netstat` | Fallback collection path when direct access is limited |
| Flask | Optional local API |
| Waitress | Optional production-style API serving |
| SQLite | Persistent scan and alert history |
| `ipaddress` | Public IP and allowlist validation |
| `json` | Alert and scan export |
| Windows Service support | Scheduled background monitoring on Windows |

## 5. System Architecture

```text
User / Windows Host
    |
    v
Connection Collection Layer
    |- psutil
    |- netstat fallback
    |
    v
Parsing + Process Enrichment
    |
    v
Detection Engine
    |- Suspicious ports
    |- Suspicious process names
    |- Suspicious command lines
    |- High outbound frequency
    |- Many unique remote IPs
    |- Periodic beacon detection
    |- Optional threat intelligence scoring
    |
    v
Storage and Output Layer
    |- Terminal UI
    |- CLI summary
    |- JSONL logs
    |- SQLite history
    |- HTTP API
    |- Safe Share Report
```

## 6. Methodology

### Step 1: Connection Collection

The system primarily uses `psutil` to collect:

- protocol
- local IP and port
- remote IP and port
- state
- PID

If needed, it can fall back to `netstat` parsing.

### Step 2: Process Context Enrichment

Each connection is enriched with process metadata such as:

- process name
- executable path
- command line
- traffic direction

This makes alerts more actionable than raw connection output alone.

### Step 3: Detection Logic

The detector applies multiple heuristic rules:

- `suspicious_port`
- `suspicious_process`
- `suspicious_command_line`
- `high_frequency_outbound`
- `process_many_unique_ips`
- `periodic_beacon`
- `medium_risk_ip`
- `high_risk_ip`

These rules combine behavioral checks with optional threat-intelligence context.

### Step 4: History and State Persistence

The system keeps:

- JSONL alert exports
- JSONL scan history
- SQLite-backed alert and scan history
- persistent beacon-detection state across runs

This allows investigation over time instead of only showing one-time alerts.

### Step 5: Beginner-Friendly Investigation

This project adds an important usability layer:

- guided terminal menu for non-expert users
- readable scan summaries
- explainable alerts in plain language
- privacy-safe Markdown report export

This is the main differentiator of the project.

## 7. Implementation

### Core Features

- single-scan execution
- continuous monitoring mode
- guided terminal interface
- Windows Service support
- structured storage using JSONL and SQLite
- optional API endpoints for summaries and history
- safe share report generation

### Unique Feature: Safe Share Report + Explainable Alerts

The project includes a privacy-safe report generator that creates a Markdown incident summary. It is designed for sharing with faculty, teammates, or reviewers without exposing sensitive machine data.

The report:

- hides local IP addresses behind aliases like `local-host-1`
- hides remote IP addresses behind aliases like `remote-host-1`
- redacts full executable paths
- masks full command-line content and tokens
- explains why each alert was flagged
- states severity in simple language
- includes false-positive notes
- provides next investigation steps

This transforms the tool from a technical detector into a more usable security assistant.

### Example Commands

```powershell
python -m hids --terminal
python -m hids --watch --interval 5 --iterations 0
python -m hids --share-report
```

### Example Scan Output

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
 2. [HIGH] suspicious command line  powershell.exe (PID 4321)    -> 104.16.0.1:443      | score 82
```

### Example Safe Share Report Output

```text
### Finding 1: Connection used a high-risk port

- Severity: HIGH (score 82)
- Detection rule: `suspicious_port`
- Why it matters: Ports such as 4444 or 5555 are often used by reverse shells or unauthorized remote tools.
- Observed process: python.exe (PID 4242)
- Local endpoint alias: local-host-1:55000
- Remote endpoint alias: remote-host-1:4444
- Process path: <redacted-path>/python.exe
- Command line: Redacted command line for python.exe (4 tokens hidden)
- False-positive note: Developer tools and lab software can also trigger this rule.
```

## 8. Testing and Results

The project includes automated unit tests for:

- connection parsing
- configuration loading
- detector rules
- logger behavior
- service history
- Windows Service helpers
- CLI parsing
- privacy-safe report generation and redaction

Current verification includes:

- suspicious port detection
- suspicious command-line detection
- high outbound volume detection
- unique IP spread detection
- periodic beacon detection
- persisted alert history loading
- safe report redaction of IPs, command lines, and file paths

Result:

- the detector correctly raises alerts for the implemented rule set
- storage and history components work as expected
- the privacy-safe report feature successfully hides sensitive fields while keeping investigation context useful

## 9. Security Analysis

### Strengths

- process-aware detection instead of raw connection-only output
- multiple detection rules covering ports, behavior, and reputation
- persistent history for later investigation
- beginner-friendly terminal interface
- privacy-safe sharing workflow
- useful for demonstrations, labs, and lightweight endpoint review

### Limitations

- heuristic-based rules can still produce false positives
- encrypted payload contents are not inspected
- advanced malware living inside trusted processes may avoid simple rules
- reputation feeds are optional and may be noisy or incomplete
- this is a monitoring and triage tool, not an automatic blocking platform

## 10. Future Enhancements

- learning mode that builds a baseline of normal host behavior over several days
- incident timeline view showing how process-to-IP behavior evolves over time
- richer alert grouping and correlation
- dashboard visualization for alert trends
- stronger export controls and selective redaction profiles
- integration with additional external security tools or feeds

## 11. Real-World Applications

- cybersecurity labs and student demonstrations
- beginner-friendly endpoint monitoring on Windows
- small-team incident triage
- local investigation before escalating to a SOC or senior analyst
- privacy-aware sharing of findings in classrooms or project reviews

## 12. Conclusion

This project demonstrates that a useful HIDS is not only about detecting suspicious behavior. It is also about making that detection understandable and shareable. By combining process-aware monitoring, persistent history, guided terminal workflows, and privacy-safe reporting, the system becomes much more approachable for non-expert users.

The most important contribution of this project is its direction:

- not just another rule-based detector
- but a beginner-friendly, privacy-safe security assistant

## 13. Project Value

This project can be positioned as:

- a practical Windows HIDS prototype
- a mini SIEM-style monitoring utility for endpoint behavior
- a beginner-focused security investigation assistant
- a privacy-aware incident reporting tool for students and small teams

Its strongest value is not only detection. Its strongest value is reducing the gap between technical security output and normal users who need to understand, investigate, and safely share what they found.
