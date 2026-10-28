import tempfile
import unittest
from pathlib import Path

from logsentinel import analyse_log


class TestLogSentinel(unittest.TestCase):
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

    def test_empty_log(self):
        results = self.analyse_lines([])

        self.assertEqual(results["total_failed_login_events"], 0)
        self.assertEqual(results["unique_source_ips"], 0)
        self.assertEqual(results["alerts"], [])


if __name__ == "__main__":
    unittest.main()
