
import unittest
from datetime import datetime, timedelta, timezone

from detector import detect_threats


class TestThreatDetection(unittest.TestCase):

    def setUp(self):
        self.start = datetime(
            2026, 10, 30, 10, 0,
            tzinfo=timezone.utc
        )

    def event(self, minute, status, username="student",
              ip="127.0.0.1"):
        return {
            "timestamp": self.start + timedelta(minutes=minute),
            "username": username,
            "source_ip": ip,
            "event_type": "login",
            "status": status
        }

    def test_normal_activity(self):
        events = [
            self.event(0, "success"),
            self.event(1, "success")
        ]
        self.assertEqual(len(detect_threats(events)), 0)

    def test_below_threshold(self):
        events = [
            self.event(i, "failed")
            for i in range(4)
        ]
        self.assertEqual(len(detect_threats(events)), 0)

    def test_brute_force_detection(self):
        events = [
            self.event(i, "failed")
            for i in range(5)
        ]
        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "Medium")

    def test_success_after_failures(self):
        events = [
            self.event(i, "failed")
            for i in range(5)
        ]
        events.append(self.event(5, "success"))

        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 2)
        self.assertTrue(any(
            a["severity"] == "High"
            for a in alerts
        ))

    def test_separate_accounts(self):
        events = [
            self.event(i, "failed", username="alice")
            for i in range(4)
        ]
        events += [
            self.event(i, "failed", username="bob")
            for i in range(4)
        ]

        self.assertEqual(len(detect_threats(events)), 0)

    def test_failures_outside_window(self):
        events = [
            self.event(i * 6, "failed")
            for i in range(5)
        ]

        self.assertEqual(len(detect_threats(events)), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
