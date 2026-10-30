"""LogSentinel: analyse SSH authentication logs for repeated failed logins."""

import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import sys

DEFAULT_LOG_FILE = Path("logs/auth.log")
DEFAULT_REPORT_FILE = Path("reports/analysis-report.json")
DEFAULT_THRESHOLD = 3
DEFAULT_WINDOW_MINUTES = 10

FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\S+) port \d+"
)


def parse_timestamp(value: str, reference_date: datetime) -> datetime:
    """Infer the closest plausible year for a yearless syslog timestamp."""
    if reference_date.tzinfo is None:
        reference_date = reference_date.replace(tzinfo=timezone.utc)
    else:
        reference_date = reference_date.astimezone(timezone.utc)

    candidates = []
    for year in (reference_date.year - 1, reference_date.year, reference_date.year + 1):
        try:
            candidate = datetime.strptime(
                f"{year} {value}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            candidates.append(candidate)
        except ValueError:
            continue

    if not candidates:
        raise ValueError(f"Invalid syslog timestamp: {value}")

    return min(candidates, key=lambda item: abs((item - reference_date).total_seconds()))


def analyse_log(
    log_file: Path,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    reference_date: datetime | None = None,
) -> dict:
    """Analyse SSH failed-password events and identify bursts per source IP."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    log_file = Path(log_file)
    reference_date = reference_date or datetime.now(timezone.utc)
    events_by_ip = defaultdict(list)
    unparsed_failed_events = 0

    with log_file.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            if "Failed password for " not in line:
                continue

            match = FAILED_LOGIN_PATTERN.search(line)
            if not match:
                unparsed_failed_events += 1
                continue

            try:
                source_ip = str(ipaddress.ip_address(match.group("ip")))
                timestamp = parse_timestamp(match.group("timestamp"), reference_date)
            except ValueError:
                unparsed_failed_events += 1
                continue

            events_by_ip[source_ip].append(timestamp)

    alerts = []
    total_failed_events = sum(len(events) for events in events_by_ip.values())
    window = timedelta(minutes=window_minutes)

    for source_ip, timestamps in events_by_ip.items():
        timestamps.sort()
        recent_events = deque()
        peak_count = 0
        peak_end = None

        for timestamp in timestamps:
            while recent_events and timestamp - recent_events[0] > window:
                recent_events.popleft()

            recent_events.append(timestamp)
            if len(recent_events) > peak_count:
                peak_count = len(recent_events)
                peak_end = timestamp

        if peak_count >= threshold:
            alerts.append({
                "source_ip": source_ip,
                "failed_attempts_in_window": peak_count,
                "window_minutes": window_minutes,
                "window_end": peak_end.isoformat(),
            })

    alerts.sort(
        key=lambda item: (-item["failed_attempts_in_window"], item["source_ip"])
    )

    return {
        "total_failed_login_events": total_failed_events,
        "unique_source_ips": len(events_by_ip),
        "unparsed_failed_events": unparsed_failed_events,
        "alerts": alerts,
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyse SSH authentication logs for repeated failed logins."
    )
    parser.add_argument(
        "-i", "--input", type=Path, default=DEFAULT_LOG_FILE,
        help=f"Input SSH log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=DEFAULT_REPORT_FILE,
        help=f"JSON report path (default: {DEFAULT_REPORT_FILE})",
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=f"Failed attempts required for an alert (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "-w", "--window", type=int, default=DEFAULT_WINDOW_MINUTES,
        help=f"Rolling detection window in minutes (default: {DEFAULT_WINDOW_MINUTES})",
    )
    return parser


def main(argv=None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window < 1:
        parser.error("--window must be at least 1")

    if not args.input.is_file():
        print(f"Error: input log file not found: {args.input}", file=sys.stderr)
        return 1

    try:
        results = analyse_log(args.input, args.threshold, args.window)
    except (OSError, UnicodeError) as error:
        print(f"Error reading log file: {error}", file=sys.stderr)
        return 1

    report = {
        "tool": "LogSentinel",
        "version": "0.2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(args.input),
        "threshold": args.threshold,
        "window_minutes": args.window,
        **results,
    }

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except OSError as error:
        print(f"Error writing report: {error}", file=sys.stderr)
        return 1

    print("LogSentinel - SSH Authentication Log Analysis")
    print("=" * 48)
    print(f"Failed login events: {results['total_failed_login_events']}")
    print(f"Unique source IPs: {results['unique_source_ips']}")
    print(f"Alert threshold: {args.threshold}")
    print(f"Detection window: {args.window} minutes")
    print()

    if results["alerts"]:
        for alert in results["alerts"]:
            print(
                f"[ALERT] {alert['source_ip']}: "
                f"{alert['failed_attempts_in_window']} failed attempts "
                f"within {args.window} minutes"
            )
    else:
        print("No source IP reached the alert threshold.")

    if results["unparsed_failed_events"]:
        print(
            "Warning: "
            f"{results['unparsed_failed_events']} failed-login events "
            "could not be parsed."
        )

    print(f"\nJSON report saved to: {args.output}")
    print("Analysis complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
