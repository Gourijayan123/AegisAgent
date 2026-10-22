
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure the detection package is importable regardless of the working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from threat_detector import detect_port_scans


class TestThreatDetector(unittest.TestCase):

    def setUp(self):
        # Use a fixed starting time for predictable tests.
        self.start_time = datetime(
            2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )

    def make_packet(self, port, seconds):
        # Create one sample TCP packet.
        timestamp = self.start_time + timedelta(seconds=seconds)

        return {
            "protocol": "TCP",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "dst_port": port,
            "timestamp": timestamp.isoformat(),
        }

    def test_detects_port_scan(self):
        # Five different ports within five seconds should trigger an alert.
        traffic = [
            self.make_packet(port, seconds)
            for port, seconds in [
                (21, 0), (22, 1), (23, 2), (80, 3), (443, 4)
            ]
        ]

        alerts = detect_port_scans(traffic)
        self.assertEqual(len(alerts), 1)

    def test_repeated_port_does_not_trigger_alert(self):
        # Repeated packets to one port are not five unique ports.
        traffic = [
            self.make_packet(80, seconds)
            for seconds in range(5)
        ]

        alerts = detect_port_scans(traffic)
        self.assertEqual(len(alerts), 0)

    def test_ports_outside_time_window_do_not_trigger(self):
        # Five different ports spread over 70 seconds should not trigger.
        traffic = [
            self.make_packet(port, seconds)
            for port, seconds in [
                (21, 0), (22, 17), (23, 34), (80, 51), (443, 70)
            ]
        ]

        alerts = detect_port_scans(traffic)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
