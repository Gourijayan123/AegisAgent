import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from threat_detector import detect_port_scans, write_security_reports


class TestSecurityReports(unittest.TestCase):
    def make_packet(self, port, seconds):
        timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=seconds
        )
        return {
            "protocol": "TCP",
            "src_ip": "192.168.1.20",
            "dst_ip": "192.168.1.100",
            "dst_port": port,
            "timestamp": timestamp.isoformat(),
        }

    def test_port_scan_matches_ai_report_schema(self):
        traffic = [
            self.make_packet(port, seconds)
            for seconds, port in enumerate([21, 22, 23, 80, 443])
        ]

        reports = detect_port_scans(traffic)

        self.assertEqual(reports, [{
            "source_ip": "192.168.1.20",
            "threat_category": "Port Scan",
            "severity": "High",
            "evidence": [
                "Multiple destination ports contacted",
                "High connection frequency",
            ],
            "threat_intelligence": {"reputation": "Unknown"},
            "recommended_investigation": [
                "Review connection history",
                "Check destination host activity",
            ],
        }])

    def test_reports_are_written_as_json(self):
        reports = [{"source_ip": "192.168.1.20"}]

        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "security_reports.json"
            write_security_reports(reports, report_file)
            self.assertEqual(json.loads(report_file.read_text()), reports)


if __name__ == "__main__":
    unittest.main()
