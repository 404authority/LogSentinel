import tempfile
import unittest
from pathlib import Path

from logsentinel import analyse_log


class TestLogSentinel(unittest.TestCase):
    def test_counts_failed_logins_by_ip(self):
        sample_log = (
            "Oct 28 09:01:12 kali sshd[1201]: Failed password for "
            "invalid user admin from 192.168.1.50 port 51234 ssh2\n"
            "Oct 28 09:01:18 kali sshd[1202]: Failed password for "
            "root from 192.168.1.50 port 51240 ssh2\n"
            "Oct 28 09:02:02 kali sshd[1203]: Accepted password for "
            "authority404 from 192.168.1.20 port 52001 ssh2\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(sample_log, encoding="utf-8")
            results = analyse_log(log_path)

        self.assertEqual(results["192.168.1.50"], 2)
        self.assertNotIn("192.168.1.20", results)

    def test_counts_multiple_source_ips(self):
        sample_log = (
            "Oct 28 09:01:12 kali sshd[1201]: Failed password for "
            "admin from 192.168.1.50 port 51234 ssh2\n"
            "Oct 28 09:01:18 kali sshd[1202]: Failed password for "
            "root from 10.0.0.25 port 51240 ssh2\n"
            "Oct 28 09:01:25 kali sshd[1203]: Failed password for "
            "guest from 192.168.1.50 port 51245 ssh2\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(sample_log, encoding="utf-8")
            results = analyse_log(log_path)

        self.assertEqual(results["192.168.1.50"], 2)
        self.assertEqual(results["10.0.0.25"], 1)

    def test_empty_log_returns_no_failed_attempts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text("", encoding="utf-8")
            results = analyse_log(log_path)

        self.assertEqual(sum(results.values()), 0)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
