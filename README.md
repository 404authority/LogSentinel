# LogSentinel

**LogSentinel** is a Python-based Linux authentication log analyser developed as part of the 404authority cybersecurity portfolio.

It parses SSH authentication logs, counts failed login attempts by source IP, detects bursts of failed logins within a rolling time window, and exports a JSON report.

## Features

- Parses SSH failed-password events.
- Groups failed login attempts by source IP.
- Detects at least three failed attempts within a rolling 10-minute window.
- Reports the number of failed attempts in each detected window.
- Exports analysis results to JSON.
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

## Requirements

- Python 3.10 or later
- No third-party Python packages required

## Usage

Run the analyser from the project directory:

    python3 logsentinel.py

The tool reads `logs/auth.log` and generates `reports/analysis-report.json`.

## Run the Tests

    python3 -m unittest discover -s tests -v

The tests cover time-window detection, failures spread outside the detection window, successful logins, and empty logs.

## Sample Detection

The included fictional sample log produces alerts for:

- `192.168.1.50`
- `10.0.0.25`

Each address has at least three failed login attempts within a 10-minute window.

All included log entries use fictional lab data. They do not indicate real attacks.

## Limitations

- The parser targets a specific SSH syslog format.
- Log timestamps omit the year and timezone; the current implementation assumes the current year and UTC.
- The analyser detects bursts but does not establish that an attack occurred.
- IP address format matching does not fully validate IP addresses.
- The tool does not block IP addresses or change system settings.
- Only synthetic sample logs are included.

## Future Improvements

- Configurable thresholds and detection windows.
- Better handling of year boundaries and timezone information.
- Support for additional authentication log formats.
- More robust IP address validation.
- Additional error handling.

## Author

**404authority** — cybersecurity learning and security tooling portfolio.
