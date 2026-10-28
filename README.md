# LogSentinel

**LogSentinel** is a Python-based Linux authentication log analyser developed as part of the 404authority cybersecurity portfolio.

It scans SSH authentication logs, counts failed login attempts by source IP, flags IPs that reach a configurable threshold, and generates a JSON report.

## Features

- Parses SSH failed-password events.
- Counts failed login attempts by source IP address.
- Flags IPs that meet or exceed the configured threshold.
- Displays alerts in the terminal.
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
└── README.md
```

## Requirements

- Python 3.10 or later
- No third-party Python packages required

## Usage

Clone the repository, then enter the project directory.

Run the analyser:

```bash
python3 logsentinel.py
```

The tool reads `logs/auth.log`, reports failed-login counts, flags source IPs with three or more failed attempts, and writes `reports/analysis-report.json`.

## Run the Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover counting failed attempts, handling multiple source IPs, and processing an empty log.

## Sample Detection

With the included sample data, LogSentinel identifies repeated failed login attempts from:

- `192.168.1.50`
- `10.0.0.25`

These addresses are part of fictional lab data and do not indicate real attacks.

## Limitations

- The current version detects failed-password events matching a specific SSH log format.
- It counts attempts across the entire file rather than within a time window.
- A threshold alert indicates suspicious activity, not proof of a brute-force attack.
- The tool does not automatically block IP addresses or change system settings.
- Only synthetic sample logs are included for demonstration.

## Future Improvements

- Time-window-based detection.
- More robust IP address validation.
- Support for additional authentication log formats.
- Improved error handling and summary reporting.

## Author

**404authority** — cybersecurity learning and security tooling portfolio.
