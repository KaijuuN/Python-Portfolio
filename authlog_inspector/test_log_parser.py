import unittest
from main import parse_log_lines_into_dict


class TestLogParser(unittest.TestCase):

    def setUp(self):
        self.sample_logs = [
            "Mar 27 13:06:56 ip-10-77-20-248 sshd[1291]: Accepted password for john from 192.168.0.101 port 22 ssh2",
            "Mar 27 13:06:56 ip-10-77-20-248 sshd[1292]: Failed password for invalid user admin from 203.0.113.42 port 22 ssh2",
            "Mar 27 13:06:56 ip-10-77-20-248 sudo: pam_unix(sudo:session): session opened for user root by john(uid=0)",
        ]

    def test_parsing_structure(self):
        parsed = parse_log_lines_into_dict(self.sample_logs)

        self.assertIn("Timestamp", parsed)
        self.assertIn("Service", parsed)
        self.assertEqual(len(parsed["Timestamp"]), 3)
        self.assertEqual(len(parsed["Service"]), 3)

    def test_first_entry(self):
        parsed = parse_log_lines_into_dict(self.sample_logs)
        self.assertEqual(parsed["Service"][0], "sshd")
        self.assertEqual(parsed["Status"][0], "Success")
        self.assertEqual(parsed["Validity"][0], "valid")
        self.assertEqual(parsed["User"][0], "valid_user_basic john")
        self.assertEqual(parsed["IP"][0], "192.168.0.101")

    def test_invalid_user(self):
        parsed = parse_log_lines_into_dict(self.sample_logs)
        self.assertIn("invalid", parsed["Validity"][1])
        self.assertIn("Failed", parsed["Status"][1])
        self.assertIn("admin", parsed["User"][1])

    def test_sudo_event(self):
        parsed = parse_log_lines_into_dict(self.sample_logs)
        self.assertIn("sudo_usage", parsed["Eventtype"][2])
        self.assertIn("Success", parsed["Status"][2])


if __name__ == "__main__":
    unittest.main()
