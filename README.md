# LogSentinel

**LogSentinel** is a Python-based Linux authentication log analyser developed as part of the 404authority cybersecurity portfolio.

It analyses SSH authentication logs, counts failed password attempts by source IP, detects bursts within a rolling time window, and exports a JSON report.

## Features

- Parses SSH failed-password events from syslog-style authentication logs.
- Groups valid failed-login events by source IP.
- Supports IPv4 and IPv6 address validation.
- Detects repeated failures using a rolling time window.
- Configurable alert threshold and detection window.
- Infers the most plausible year for syslog timestamps that omit the year.
- Reports malformed or invalid failed-login events separately.
- Exports results to JSON.
- Uses only the Python standard library.
- Includes automated unit tests.

## Project Structure

```text
LogSentinel/
├── logs/
│   └── auth.log
├── reports/
│   └── analysis-report.json
├── tests/
│   └── test_logsentinel.py
├── logsentinel.py
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or later
- No third-party Python packages

## Usage

Run from the project directory with the default settings:

```bash
python3 logsentinel.py
```

The default input is `logs/auth.log`; the default JSON report is `reports/analysis-report.json`.

### Command-line options

```text
-i, --input       Input authentication log
-o, --output      JSON report destination
-t, --threshold   Failed attempts required for an alert (default: 3)
-w, --window      Rolling window in minutes (default: 10)
```

Example using a different log and detection settings:

```bash
python3 logsentinel.py --input logs/auth.log --output reports/custom-report.json --threshold 5 --window 15
```

View all options:

```bash
python3 logsentinel.py --help
```

## Run the Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover timestamp year inference, IPv4 and IPv6 validation, rolling-window boundaries, per-IP detection, malformed events, configurable thresholds, and empty logs.

## Sample Detection

The included fictional sample log contains failed login bursts from:

- `192.168.1.50`
- `10.0.0.25`

Both addresses reach the default threshold of three failed attempts within ten minutes.

All included log entries use fictional lab data. They do not indicate real attacks.

## Detection Logic

For each source IP, LogSentinel sorts the parsed event timestamps and maintains a rolling queue. Events older than the configured window are removed. The largest number of events present in any window is compared with the alert threshold.

The window boundary is inclusive: an event exactly ten minutes before the current event remains in a ten-minute window.

## Limitations

- The parser targets SSH `Failed password` messages in a syslog-style format; it is not a general-purpose parser for every Linux authentication log.
- Standard syslog timestamps omit the year and timezone. The tool infers the closest year relative to the current UTC date and assumes timestamps are UTC.
- Year inference may be inaccurate for old logs, logs spanning multiple years, or logs whose local timezone differs from UTC.
- The tool identifies repeated failed logins; it does not prove that an attack occurred.
- The tool does not block IP addresses or modify system settings.
- The included sample data is synthetic.

## Author

**404authority** — cybersecurity learning and security tooling portfolio.
