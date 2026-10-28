import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone

from logsentinel import analyse_log, parse_timestamp


class TestLogSentinel(unittest.TestCase):

    def test_parse_timestamp_uses_nearest_year(self):
         reference = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)

         timestamp = parse_timestamp("Dec 31 23:59:59", reference)

         self.assertEqual(timestamp.year, 2025)
         self.assertEqual(timestamp.month, 12)
         self.assertEqual(timestamp.day, 31)
         self.assertEqual(timestamp.tzinfo, timezone.utc)


    def test_parse_timestamp_uses_current_year_when_closest(self):
        reference = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)

        timestamp = parse_timestamp("Oct 28 09:01:12", reference)

        self.assertEqual(timestamp.year, 2026)
        self.assertEqual(timestamp.month, 10)

    def analyse_lines(self, lines):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "auth.log"
            log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return analyse_log(log_file)

    def test_detects_three_failures_within_ten_minutes(self):
        results = self.analyse_lines([
            "Oct 28 09:01:12 kali sshd[1201]: Failed password for admin from 192.168.1.50 port 51234 ssh2",
            "Oct 28 09:01:18 kali sshd[1202]: Failed password for admin from 192.168.1.50 port 51240 ssh2",
            "Oct 28 09:04:25 kali sshd[1203]: Failed password for root from 192.168.1.50 port 51245 ssh2",
        ])

        self.assertEqual(results["total_failed_login_events"], 3)
        self.assertEqual(len(results["alerts"]), 1)
        self.assertEqual(results["alerts"][0]["source_ip"], "192.168.1.50")
        self.assertEqual(results["alerts"][0]["failed_attempts_in_window"], 3)

    def test_does_not_alert_when_failures_are_spread_out(self):
        results = self.analyse_lines([
            "Oct 28 09:01:12 kali sshd[1201]: Failed password for admin from 192.168.1.50 port 51234 ssh2",
            "Oct 28 09:20:18 kali sshd[1202]: Failed password for admin from 192.168.1.50 port 51240 ssh2",
            "Oct 28 09:40:25 kali sshd[1203]: Failed password for root from 192.168.1.50 port 51245 ssh2",
        ])

        self.assertEqual(results["total_failed_login_events"], 3)
        self.assertEqual(results["alerts"], [])

    def test_ignores_successful_logins(self):
        results = self.analyse_lines([
            "Oct 28 09:01:12 kali sshd[1201]: Failed password for admin from 192.168.1.50 port 51234 ssh2",
            "Oct 28 09:02:02 kali sshd[1202]: Accepted password for authority404 from 192.168.1.20 port 52001 ssh2",
        ])

        self.assertEqual(results["total_failed_login_events"], 1)
        self.assertEqual(results["unique_source_ips"], 1)
        self.assertEqual(results["alerts"], [])

    def test_rejects_invalid_ip_address(self):
        results = self.analyse_lines([
            "Oct 28 09:01:12 kali sshd[1201]: Failed password for admin from 999.999.999.999 port 51234 ssh2",
        ])

        self.assertEqual(results["total_failed_login_events"], 0)
        self.assertEqual(results["unique_source_ips"], 0)
        self.assertEqual(results["unparsed_failed_events"], 1)
        self.assertEqual(results["alerts"], [])

    def test_detects_failures_exactly_ten_minutes_apart(self):
        results = self.analyse_lines([
            "Oct 28 09:00:00 kali sshd[1201]: Failed password for admin from 192.168.1.50 port 51234 ssh2",
            "Oct 28 09:05:00 kali sshd[1202]: Failed password for admin from 192.168.1.50 port 51240 ssh2",
            "Oct 28 09:10:00 kali sshd[1203]: Failed password for root from 192.168.1.50 port 51245 ssh2",
        ])

        self.assertEqual(results["total_failed_login_events"], 3)
        self.assertEqual(len(results["alerts"]), 1)
        self.assertEqual(results["alerts"][0]["failed_attempts_in_window"], 3)

    def test_rejects_impossible_timestamp(self):
        results = self.analyse_lines([
            "Feb 30 09:01:12 kali sshd[1201]: Failed password for admin from 192.168.1.50 port 51234 ssh2",
        ])

        self.assertEqual(results["total_failed_login_events"], 0)
        self.assertEqual(results["unparsed_failed_events"], 1)
        self.assertEqual(results["alerts"], [])

    def test_empty_log(self):
        results = self.analyse_lines([])

        self.assertEqual(results["total_failed_login_events"], 0)
        self.assertEqual(results["unique_source_ips"], 0)
        self.assertEqual(results["alerts"], [])


if __name__ == "__main__":
    unittest.main()
