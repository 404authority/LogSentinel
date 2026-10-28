from collections import Counter
from pathlib import Path
import re

from collections import Counter
from pathlib import Path
import re

LOG_FILE = Path("logs/auth.log")
FAILED_LOGIN_THRESHOLD = 3

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyse_log(log_file: Path) -> Counter:
    """Count failed SSH login attempts by source IP."""
    failed_attempts = Counter()

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                failed_attempts[match.group("ip")] += 1

    return failed_attempts


def main() -> None:
    if not LOG_FILE.exists():
        print(f"Error: log file not found: {LOG_FILE}")
        return

    failed_attempts = analyse_log(LOG_FILE)

    print("LogSentinel - SSH Authentication Log Analysis")
    print("=" * 48)
    print(f"Failed login events: {sum(failed_attempts.values())}")
    print(f"Unique source IPs: {len(failed_attempts)}")
    print()

    alerts_found = False

    for ip, count in failed_attempts.most_common():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts_found = True
            print(
                f"[ALERT] {ip}: {count} failed login attempts "
                f"(threshold: {FAILED_LOGIN_THRESHOLD})"
            )

    if not alerts_found:
        print("No source IP reached the alert threshold.")

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()


from collections import Counter
from pathlib import Path
import json
import re
from datetime import datetime, timezone

LOG_FILE = Path("logs/auth.log")
REPORT_FILE = Path("reports/analysis-report.json")
FAILED_LOGIN_THRESHOLD = 3

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyse_log(log_file: Path) -> Counter:
    """Count failed SSH login attempts by source IP."""
    failed_attempts = Counter()

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                failed_attempts[match.group("ip")] += 1

    return failed_attempts


def main() -> None:
    if not LOG_FILE.exists():
        print(f"Error: log file not found: {LOG_FILE}")
        return

    failed_attempts = analyse_log(LOG_FILE)
    total_failed = sum(failed_attempts.values())

    alerts = [
        {"source_ip": ip, "failed_attempts": count}
        for ip, count in failed_attempts.most_common()
        if count >= FAILED_LOGIN_THRESHOLD
    ]

    report = {
        "tool": "LogSentinel",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(LOG_FILE),
        "threshold": FAILED_LOGIN_THRESHOLD,
        "total_failed_login_events": total_failed,
        "unique_source_ips": len(failed_attempts),
        "alerts": alerts,
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("LogSentinel - SSH Authentication Log Analysis")
    print("=" * 48)
    print(f"Failed login events: {total_failed}")
    print(f"Unique source IPs: {len(failed_attempts)}")
    print()

    if alerts:
        for alert in alerts:
            print(
                f"[ALERT] {alert['source_ip']}: "
                f"{alert['failed_attempts']} failed login attempts "
                f"(threshold: {FAILED_LOGIN_THRESHOLD})"
            )
    else:
        print("No source IP reached the alert threshold.")

    print(f"\nJSON report saved to: {REPORT_FILE}")
    print("Analysis complete.")


if __name__ == "__main__":
    main()
