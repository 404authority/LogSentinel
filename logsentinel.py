from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress
import json
import re

LOG_FILE = Path("logs/auth.log")
REPORT_FILE = Path("reports/analysis-report.json")

FAILED_LOGIN_THRESHOLD = 3
WINDOW_MINUTES = 10

FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s"
    r"\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_timestamp(
    value: str,
    reference_date: datetime,
) -> datetime:
    """Infer the most plausible year for a yearless SSH syslog timestamp."""
    candidates = []

    for year in (
        reference_date.year - 1,
        reference_date.year,
        reference_date.year + 1,
    ):
        try:
            candidate = datetime.strptime(
                f"{year} {value}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            candidates.append(candidate)
        except ValueError:
            continue

    if not candidates:
        raise ValueError(f"Invalid syslog timestamp: {value}")

    reference = reference_date
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    else:
        reference = reference.astimezone(timezone.utc)

    return min(
        candidates,
        key=lambda candidate: abs((candidate - reference).total_seconds()),
    )

def analyse_log(log_file: Path) -> dict:
    """Analyse failed SSH logins and detect bursts within a time window."""
    failed_attempts = Counter()
    events_by_ip = defaultdict(list)
    reference_date = datetime.now(timezone.utc)
    unparsed_failed_events = 0

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            if "Failed password for " not in line:
                continue

            match = FAILED_LOGIN_PATTERN.search(line)

            ip = match.group("ip")

            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                unparsed_failed_events += 1
                continue

            try:
                timestamp = parse_timestamp(
                    match.group("timestamp"), reference_date
                )
            except ValueError:
                unparsed_failed_events += 1
                continue

            failed_attempts[ip] += 1
            events_by_ip[ip].append(timestamp)

    window = timedelta(minutes=WINDOW_MINUTES)
    alerts = []

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()
        recent_events = deque()
        peak_count = 0
        peak_end = None

        for timestamp in timestamps:
            while (
                recent_events
                and timestamp - recent_events[0] > window
            ):
                recent_events.popleft()

            recent_events.append(timestamp)

            if len(recent_events) > peak_count:
                peak_count = len(recent_events)
                peak_end = timestamp

        if peak_count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "source_ip": ip,
                "failed_attempts_in_window": peak_count,
                "window_minutes": WINDOW_MINUTES,
                "window_end": peak_end.isoformat(),
            })

    alerts.sort(
        key=lambda item: item["failed_attempts_in_window"],
        reverse=True,
    )

    return {
        "total_failed_login_events": sum(failed_attempts.values()),
        "unique_source_ips": len(failed_attempts),
        "unparsed_failed_events": unparsed_failed_events,
        "alerts": alerts,
    }


def main() -> None:
    if not LOG_FILE.exists():
        print(f"Error: log file not found: {LOG_FILE}")
        return

    results = analyse_log(LOG_FILE)

    report = {
        "tool": "LogSentinel",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(LOG_FILE),
        "threshold": FAILED_LOGIN_THRESHOLD,
        "window_minutes": WINDOW_MINUTES,
        **results,
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("LogSentinel - SSH Authentication Log Analysis")
    print("=" * 48)
    print(f"Failed login events: {results['total_failed_login_events']}")
    print(f"Unique source IPs: {results['unique_source_ips']}")
    print(f"Detection window: {WINDOW_MINUTES} minutes")
    print()

    if results["alerts"]:
        for alert in results["alerts"]:
            print(
                f"[ALERT] {alert['source_ip']}: "
                f"{alert['failed_attempts_in_window']} failed attempts "
                f"within {WINDOW_MINUTES} minutes"
            )
    else:
        print("No source IP reached the alert threshold.")

    if results["unparsed_failed_events"]:
        print(
            "Warning: "
            f"{results['unparsed_failed_events']} failed-login events "
            "could not be parsed."
        )

    print(f"\nJSON report saved to: {REPORT_FILE}")
    print("Analysis complete.")


if __name__ == "__main__":
    main()
