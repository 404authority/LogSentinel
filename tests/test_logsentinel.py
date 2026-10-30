import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from logsentinel import analyse_log, parse_timestamp


REFERENCE = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


class TestLogSentinel(unittest.TestCase):
    def analyse_lines(self, lines, threshold=3, window_minutes=10):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "auth.log"
            log_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            return analyse_log(
                log_file, threshold, window_minutes, reference_date=REFERENCE
            )

    def event(self, timestamp, ip="192.168.1.50", user="admin"):
        return (
            f"{timestamp} kali sshd[1201]: Failed password for {user} "
            f"from {ip} port 51234 ssh2"
        )

    def test_parse_timestamp_uses_nearest_year_across_year_boundary(self):
        reference = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)
        parsed = parse_timestamp("Dec 31 23:59:59", reference)
        self.assertEqual(parsed.year, 2025)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_parse_timestamp_uses_reference_year_when_closest(self):
        parsed = parse_timestamp("Oct 28 09:01:12", REFERENCE)
        self.assertEqual(parsed.year, 2026)

    def test_detects_three_failures_within_ten_minutes(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:01:12"),
            self.event("Oct 28 09:01:18"),
            self.event("Oct 28 09:04:25", user="root"),
        ])
        self.assertEqual(results["total_failed_login_events"], 3)
        self.assertEqual(results["unique_source_ips"], 1)
        self.assertEqual(results["alerts"][0]["failed_attempts_in_window"], 3)

    def test_does_not_alert_when_failures_are_spread_out(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:01:12"),
            self.event("Oct 28 09:20:18"),
            self.event("Oct 28 09:40:25"),
        ])
        self.assertEqual(results["alerts"], [])

    def test_successful_login_is_ignored(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:01:12"),
            "Oct 28 09:02:02 kali sshd[1202]: Accepted password for user "
            "from 192.168.1.20 port 52001 ssh2",
        ])
        self.assertEqual(results["total_failed_login_events"], 1)

    def test_invalid_ip_is_counted_as_unparsed(self):
        results = self.analyse_lines([self.event("Oct 28 09:01:12", "999.999.999.999")])
        self.assertEqual(results["total_failed_login_events"], 0)
        self.assertEqual(results["unparsed_failed_events"], 1)

    def test_supports_ipv6_addresses(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:01:12", "2001:db8::1"),
            self.event("Oct 28 09:02:12", "2001:db8::1"),
            self.event("Oct 28 09:03:12", "2001:db8::1"),
        ])
        self.assertEqual(results["unique_source_ips"], 1)
        self.assertEqual(results["alerts"][0]["source_ip"], "2001:db8::1")

    def test_rejects_invalid_ipv6_address(self):
        results = self.analyse_lines([self.event("Oct 28 09:01:12", "2001:db8:::1")])
        self.assertEqual(results["unparsed_failed_events"], 1)

    def test_exact_window_boundary_is_included(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:00:00"),
            self.event("Oct 28 09:05:00"),
            self.event("Oct 28 09:10:00"),
        ])
        self.assertEqual(results["alerts"][0]["failed_attempts_in_window"], 3)

    def test_event_outside_window_is_removed(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:00:00"),
            self.event("Oct 28 09:00:01"),
            self.event("Oct 28 09:10:02"),
        ])
        self.assertEqual(results["alerts"], [])

    def test_custom_threshold_and_window(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:01:00"),
            self.event("Oct 28 09:02:00"),
        ], threshold=2, window_minutes=5)
        self.assertEqual(results["alerts"][0]["failed_attempts_in_window"], 2)

    def test_malformed_failed_event_is_counted(self):
        results = self.analyse_lines([
            "Oct 28 09:01:12 sshd: Failed password for user with no source address"
        ])
        self.assertEqual(results["unparsed_failed_events"], 1)

    def test_impossible_timestamp_is_counted(self):
        results = self.analyse_lines([self.event("Feb 30 09:01:12")])
        self.assertEqual(results["unparsed_failed_events"], 1)

    def test_empty_log(self):
        results = self.analyse_lines([])
        self.assertEqual(results["total_failed_login_events"], 0)
        self.assertEqual(results["unique_source_ips"], 0)
        self.assertEqual(results["alerts"], [])

    def test_each_ip_is_analysed_separately(self):
        results = self.analyse_lines([
            self.event("Oct 28 09:01:00", "192.168.1.10"),
            self.event("Oct 28 09:02:00", "192.168.1.10"),
            self.event("Oct 28 09:03:00", "192.168.1.10"),
            self.event("Oct 28 09:01:00", "192.168.1.20"),
            self.event("Oct 28 09:02:00", "192.168.1.20"),
        ])
        self.assertEqual(len(results["alerts"]), 1)
        self.assertEqual(results["alerts"][0]["source_ip"], "192.168.1.10")

    def test_invalid_threshold_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyse_log(path, threshold=0)

    def test_invalid_window_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyse_log(path, window_minutes=0)


if __name__ == "__main__":
    unittest.main()
