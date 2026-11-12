# Mini-SIEM

[![Tests](https://github.com/LeanGnzlz/Mini-SIEM/actions/workflows/tests.yml/badge.svg)](https://github.com/LeanGnzlz/Mini-SIEM/actions/workflows/tests.yml)

Educational Python tool that collects security events from different sources, normalizes them into a common format, correlates them with configurable detection rules and generates alerts with their supporting evidence.

It is built on top of my two previous projects, which act as data sources:

- [Network Scanner](https://github.com/LeanGnzlz/network-scanner-python): TCP port scanning.
- [Login Failure Detector](https://github.com/LeanGnzlz/Login-Failure-Detector): authentication log analysis.

## Goal

Understand and apply the core concepts of a SIEM (Security Information and Event Management), the tool a SOC uses to monitor and detect suspicious activity:

- Log ingestion from multiple sources
- Normalization into a single event schema
- Event correlation over time
- Alert generation with severity and MITRE ATT&CK mapping
- Reports with the evidence behind each detection

## Features

- Ingests Network Scanner JSON reports and Login Failure Detector authentication logs
- Common event model, with all timestamps converted to UTC
- Detection rules configurable in YAML, no code changes needed
- Three rule types: signature, threshold (sliding window, with distinct-value counting) and sequence
- One alert per episode, to avoid flooding the analyst with noise
- Detection rules mapped to MITRE ATT&CK techniques where one applies
- TXT and JSON reports with the evidence events of each alert
- Strict validation of data and rules: nothing is silently discarded
- Optional history in SQLite (`--db`): rules run over everything stored so far, so patterns that span several runs are detected, and analyzing the same files again never duplicates data
- Alerts that were not in the database before the run are marked `[NEW]`
- Nearly 500 automated tests with pytest, run on every push with GitHub Actions

## How it works

```mermaid
flowchart LR
    A[Network Scanner<br/>JSON reports] --> C[Adapters]
    B[Login Failure Detector<br/>auth.log] --> C
    C --> D[Ingestion<br/>stable event IDs<br/>sorted by time]
    D --> M[Merge with history]
    DB[(SQLite database<br/>optional)] -. history .-> M
    M --> E[Rules engine<br/>signature / threshold / sequence]
    R[rules.yaml] --> E
    E --> F[Alerts with evidence<br/>stable alert IDs]
    F --> G[Console output<br/>new alerts marked]
    F --> H[TXT and JSON reports]
    D -. save .-> DB
    F -. save .-> DB
```

1. **Adapters:** each source has a translator that converts its data to the common format. Invalid lines are rejected and reported, never silently lost.
2. **Ingestion:** merges the events from all sources into a single timeline sorted by time, and gives every event a stable ID derived from its content.
3. **History (optional):** with `--db`, the events already stored are merged with the new ones, so the rules see everything.
4. **Rules engine:** loads the rules from the YAML file, validates them and applies them to the events.
5. **Alerts:** each detection produces an alert with its severity, its MITRE technique when it has one, the identifiers of the events that triggered it, and a stable ID of its own.
6. **Output and storage:** alerts are printed (new ones are marked), saved to the database when one is used, and written to TXT and JSON reports on request.

### Rule types

| Type | What it detects | Included example |
|---|---|---|
| Signature | A single event that is suspicious on its own | Remote access port open |
| Threshold | N events, or N distinct values, within a time window, grouped by an entity | Brute force and password spraying |
| Sequence | Several events in a given order within a window | Failed logins followed by a successful login |

## Installation

Developed and tested with Python 3.13. Dependencies: PyYAML (rules) and pytest (tests). SQLite is part of Python's standard library.

```bash
git clone https://github.com/LeanGnzlz/Mini-SIEM.git
cd Mini-SIEM
python -m venv venv
```

Activate the virtual environment:

- Windows (PowerShell): `.\venv\Scripts\Activate.ps1`
- Linux / macOS: `source venv/bin/activate`

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

The repository includes sample input files, so you can try it right away:

```bash
python mini_siem.py --scan examples/scan_report.json --auth-log examples/auth.log
```

Save the reports to a folder:

```bash
python mini_siem.py --scan examples/scan_report.json --auth-log examples/auth.log --report-dir reports
```

### Options

| Option | Description |
|---|---|
| `--scan FILE [FILE ...]` | Network Scanner JSON report(s) |
| `--auth-log FILE [FILE ...]` | Authentication log file(s) |
| `--rules FILE` | Detection rules file (default: `rules/rules.yaml`) |
| `--report-dir DIR` | Write a JSON and a TXT report to this folder |
| `--db FILE` | SQLite database that keeps events and alerts between runs (optional) |

At least one of `--scan` or `--auth-log` is required.

### Keeping a history

With `--db`, the tool keeps events and alerts in a local SQLite file between runs:

```bash
python mini_siem.py --scan examples/scan_report.json --auth-log examples/auth.log --db data/siem.db
```

First run (excerpt):

```text
Events ingested: 14
Rejected inputs: 0
Rules loaded: 4 (4 enabled)
History: 0 event(s) loaded from data/siem.db
Events analyzed: 14
Alerts: 4 (high: 1, medium: 3), 4 new

[HIGH] R001 Sensitive port open [NEW]
  Time: 2026-06-25 16:58:39 UTC
  Remote access or file sharing port found open
  Evidence: 1 event(s)

...

Saved to data/siem.db: 14 new event(s), 4 new alert(s) (0 event(s) and 0 alert(s) already stored)
```

The same command run again (excerpt):

```text
Events ingested: 14
Rejected inputs: 0
Rules loaded: 4 (4 enabled)
History: 14 event(s) loaded from data/siem.db
Events analyzed: 14
Alerts: 4 (high: 1, medium: 3), 0 new

[HIGH] R001 Sensitive port open
  Time: 2026-06-25 16:58:39 UTC
  Remote access or file sharing port found open
  Evidence: 1 event(s)

...

Saved to data/siem.db: 0 new event(s), 0 new alert(s) (14 event(s) and 4 alert(s) already stored)
```

How it behaves:

- The stored events are loaded, the events from the files you pass are added, and the rules run over everything. Patterns that span several runs are detected, such as failed logins in yesterday's log followed by a successful login in today's.
- All the alerts found over the combined history are shown, and the ones that were not in the database before this run are marked `[NEW]`.
- Analyzing the same files again does not duplicate anything.
- Alerts are printed first and saved afterwards, so a failure while saving never hides what was detected. The tool then exits with code `2`.
- Reports written with `--report-dir` cover the whole analysis, including evidence that comes from the history. In them, `events_ingested` counts the events analyzed, history included.
- The database holds the same sensitive data as your logs. `*.db` files and the contents of `data/` are ignored by Git.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | The run finished. Finding alerts is not an error. |
| `2` | Error: invalid rules, unreadable input, unusable database or failure while saving to it, report could not be written, or wrong usage |

Input lines that cannot be parsed are reported as warnings on `stderr` and counted in the summary, and the rest of the data is still processed.

## Example output

```text
Mini-SIEM
Events ingested: 14
Rejected inputs: 0
Rules loaded: 4 (4 enabled)
Alerts: 4 (high: 1, medium: 3)

[HIGH] R001 Sensitive port open
  Time: 2026-06-25 16:58:39 UTC
  Remote access or file sharing port found open
  Evidence: 1 event(s)

[MEDIUM] R002 Brute force (T1110.001)
  Time: 2026-06-26 13:01:25 UTC
  Repeated failed logins from one IP: src_ip=185.23.44.10, 5 events within 300s
  Evidence: 5 event(s)

[MEDIUM] R002 Brute force (T1110.001)
  Time: 2026-06-26 14:00:09 UTC
  Repeated failed logins from one IP: src_ip=10.0.0.50, 5 events within 300s
  Evidence: 5 event(s)

[MEDIUM] R004 Password spraying (T1110.003)
  Time: 2026-06-26 14:00:09 UTC
  Failed logins against several different users from one IP: src_ip=10.0.0.50, 5 distinct user values within 300s
  Evidence: 5 event(s)
```

The input files store timestamps without a time zone. They are interpreted as the local time of the machine running the tool and converted to UTC, so the exact times shown depend on where it runs. The example above was generated at UTC-3.

## Reports

With `--report-dir`, each run writes two files with the same name, `siem_report_YYYYMMDD_HHMMSS.json` and `.txt`. An existing report is never overwritten.

- The **TXT** report is meant to be read by a person: summary, alerts and one line per evidence event.
- The **JSON** report is meant for other tools: the same data, plus the full original log line of every evidence event.

Excerpt from the TXT report:

```text
[HIGH] R001 Sensitive port open
  Time: 2026-06-25 16:58:39 UTC
  Remote access or file sharing port found open
  Evidence (1 event(s)):
    - 2026-06-25 16:58:39 UTC | port_open | network_scanner | dest 127.0.0.1:445
```

Reports can contain real usernames, IP addresses and log lines. The contents of `data/` and `reports/` are ignored by Git, so put your own logs in `data/` and write reports to `reports/` to avoid publishing them by accident.

## Detection rules

Rules live in `rules/rules.yaml`. Editing that file is enough to tune a threshold, disable a rule or add a new one, with no code changes.

### Included rules

| ID | Name | Type | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| R001 | Sensitive port open | Signature | high | none |
| R002 | Brute force | Threshold | medium | T1110.001 (Password Guessing) |
| R003 | Successful brute force | Sequence | high | T1110 (Brute Force) |
| R004 | Password spraying | Threshold | medium | T1110.003 (Password Spraying) |

- **R001** flags ports 23, 445, 3389 and 5900 (Telnet, SMB, RDP and VNC) found open. It has no MITRE technique on purpose: an open port is an exposure, not an observed attacker technique, and forcing a mapping would be misleading.
- **R002** fires on 5 failed logins from the same IP within 300 seconds.
- **R003** fires on 5 failed logins followed by a successful login from the same IP within 300 seconds, which suggests the attacker may have gotten in.
- **R004** fires on failed logins against 5 distinct users from the same IP within 300 seconds.

### Rule format

```yaml
rules:
  - id: R003
    name: Successful brute force
    type: sequence
    severity: high
    mitre: T1110
    description: Failed logins followed by a successful login from the same IP
    group_by: src_ip
    window_seconds: 300
    steps:
      - event_type: auth_failure
        count: 5
      - event_type: auth_success
```

Fields common to every rule:

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier |
| `name` | yes | Short name shown in alerts |
| `type` | yes | `signature`, `threshold` or `sequence` |
| `severity` | yes | `low`, `medium`, `high` or `critical` |
| `description` | no | Text shown in the alert |
| `mitre` | no | MITRE ATT&CK technique id, such as `T1110` or `T1110.001` |
| `enabled` | no | `false` loads the rule but skips it (default `true`) |

Fields specific to each type:

| Type | Fields |
|---|---|
| Signature | `event_type` (required), `dest_ports` (optional list, empty means any port) |
| Threshold | `event_type`, `group_by`, `window_seconds`, `threshold` (all required), `distinct` (optional) |
| Sequence | `group_by`, `window_seconds`, `steps` (all required, at least 2 steps; each step has an `event_type` and an optional `count`) |

Valid event types are `auth_failure`, `auth_success` and `port_open`. `group_by` accepts `src_ip`, `dest_ip` or `user`. With `distinct`, a threshold rule counts distinct values of that field instead of events, which is how password spraying (many users from one IP) is told apart from plain brute force.

### How rules are evaluated

- Events are grouped by the entity in `group_by` (for example, one counter per source IP), and events without that field are ignored.
- Time windows are sliding and inclusive: events exactly `window_seconds` apart still count together.
- A threshold rule raises one alert when the count reaches the threshold, and stays quiet while the activity continues. It can alert again only after the count drops back below the threshold, so a sustained attack produces one alert and two separate bursts produce two.
- A sequence rule matches its steps in order and ignores unrelated events in between. After it fires, the window of that group is cleared, so a second successful login right after does not alert again.
- The same event can trigger several rules. Each alert lists the identifiers of its evidence events.
- With `--db`, the rules run over the stored history plus the new events.

### Rule validation

The rules file is validated strictly and loaded all or nothing, because a rule that is silently wrong is a blind spot in detection:

- Unknown fields are rejected, which catches typos such as `windows_seconds`.
- Fields that do not apply to the rule type are rejected.
- Event types are checked against the known list, so `auth_faliure` is an error instead of a rule that never fires.
- Numbers must be real positive integers. YAML values such as `yes` or `true` are not accepted where a number is expected.
- Duplicate rule ids are rejected, and errors name the position of the offending rule.
- The file is read with `yaml.safe_load`, which never builds arbitrary Python objects.

## History and the database

### Stable identities

Every event and every alert has a deterministic ID, so analyzing the same data twice produces the same IDs and the database recognizes what it already has.

- **Event ID:** SHA-256 of the event's content (every field except the ID, with the time in UTC) plus an occurrence number. The number counts identical lines inside one file, in order, so two truly identical log lines stay two separate events, and a log that grows keeps the IDs of its old lines.
- The same event found in two different files is ingested once, and a warning says how many duplicates were skipped.
- **Alert ID:** SHA-256 of the rule id and the ordered IDs of its evidence events. The same rule with the same evidence is the same alert, and the same evidence under another rule is a different alert.
- The alert ID does not include severity or description. An alert that is already stored keeps its first version.

### Schema

| Table | Content |
|---|---|
| `events` | One row per event, with all its fields and the original log line |
| `alerts` | One row per alert |
| `alert_events` | Which events are the evidence of which alert, and in what order |

Dates are stored as ISO 8601 text in UTC, which sorts chronologically as plain text.

### Safeguards

- **No SQL injection.** Every query uses parameters (`?`) and never builds SQL by concatenating data, so a username such as `x'; DROP TABLE events; --` is stored as plain text. The tests include hostile values, and one test shows that the concatenated version of a query is injectable.
- **Constraints in the database** (`NOT NULL`, `CHECK` on severity and port range, foreign keys enabled on every connection) back up the validation of the Python models.
- **Atomic saves.** Each run is saved in a single transaction: either everything is stored or nothing is.
- **Validation when reading.** Data read back goes through the same models, so a damaged row stops the run with an error that names it.
- **Schema versioning.** The schema version is stored in the database, and a database created by a newer version is refused without touching it.
- **Idempotence.** Repeating a run does not duplicate anything.

## Project structure

```text
Mini-SIEM/
├── mini_siem.py            command line interface
├── requirements.txt
├── .github/workflows/
│   └── tests.yml           runs the tests on every push
├── adapters/
│   ├── network_scanner_adapter.py
│   └── login_detector_adapter.py
├── engine/
│   ├── event.py            event model
│   ├── alert.py            alert model
│   ├── rule.py             rule model and YAML loading
│   ├── evaluator.py        signature, threshold and sequence evaluators
│   ├── identity.py         stable IDs for events and alerts
│   ├── ingest.py           merges all sources and the history into one timeline
│   └── report.py           TXT and JSON reports
├── storage/
│   ├── db.py               SQLite connection and schema
│   └── repository.py       saves and loads events and alerts
├── rules/
│   └── rules.yaml          detection rules
├── examples/               sample input files
├── data/                   your own logs and databases (contents ignored by Git)
├── reports/                generated reports (contents ignored by Git)
└── tests/
```

## Running the tests

```bash
python -m pytest
```

The suite covers each module on its own (models, adapters, every rule type, reports, command line), the edges of the time windows, the shipped `rules.yaml`, the database (constraints, atomic saves, round trips, damaged data and SQL injection attempts), and complete runs from input files to alerts, including patterns that span several runs. Tests write only to temporary folders, so they never touch `data/` or `reports/`. The same suite runs on Ubuntu with GitHub Actions on every push.

## Known limitations

- **Timestamps without a time zone.** Neither the Network Scanner reports nor the authentication logs record a time zone, so the adapters read them as the local time of the machine running the tool. Analyzing logs from a server in another time zone produces shifted times, and because event IDs include the time, the same file analyzed from a machine in another time zone gets different IDs.
- **Scan time.** The scanner only stores when a scan finished, so every open port from one report gets that time, not the moment it was found.
- **One grouping field.** A rule groups by a single field. The brute force rule counts failures per source IP, so a password spraying attempt (5 different users from one IP) also triggers it. The example output shows this for `10.0.0.50`: R002 and R004 both fire on the same 5 events. Grouping by IP and user at the same time is planned.
- **Sequences are matched by IP and time only.** A successful login in the middle of the failures does not restart a sequence, and failures followed by a success from a shared IP (for example, behind NAT) are treated as one episode.
- **Files only.** The tool reads files and does not collect events live. Without `--db` every run starts from scratch.
- **Whole history on every run.** With `--db`, all stored events are loaded and evaluated each time. That is fine for a lab, but large volumes would need a time window.
- **No host name in the data.** The logs do not say which machine produced a line, so identical lines in different files, or in different runs, are treated as the same event.
- **Alerts keep their first version.** Changing only the severity or the description of a rule does not update alerts that are already stored.
- **All or nothing for scan reports.** A scan report with one invalid entry is rejected as a whole, while an authentication log is judged line by line.
- **Two input formats.** Only the output of the two companion projects is supported.

Two of these behaviors (grouping by source IP only and sequences that are not reset) are pinned down by tests, so changing them will be a deliberate decision.

## Future work

- Group rules by more than one field, such as IP and user
- Optional reset condition for sequence rules
- Support real log formats: Linux sshd authentication logs and Windows failed logon events (4625)
- Load only a time window of the history instead of all of it
- Simple dashboard to browse alerts
- Automated response (SOAR-style playbooks) as a separate follow-up project

## Disclaimer

Mini-SIEM is an educational project and not a replacement for a production SIEM. Use it only with data you own or are explicitly authorized to analyze. Logs, reports and databases can contain personal and sensitive information, so handle them accordingly and never publish them.