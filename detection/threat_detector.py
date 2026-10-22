"""Coordinate traffic analysis and AI-ready security report generation."""

import json
from pathlib import Path

from cybersecurity_context import build_port_scan_report
from security_rules import find_port_scans, parse_timestamp

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAFFIC_FILE = PROJECT_ROOT / "data" / "network_traffic.json"
REPORT_FILE = PROJECT_ROOT / "data" / "security_reports.json"


def detect_port_scans(traffic):
    """Detect TCP port scans and return AI-ready security reports."""
    return [build_port_scan_report(finding) for finding in find_port_scans(traffic)]


def write_security_reports(reports, report_file=REPORT_FILE):
    """Save generated reports as a JSON list for downstream AI analysis."""
    with Path(report_file).open("w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2)


def main():
    if not TRAFFIC_FILE.exists():
        raise FileNotFoundError(f"Traffic file not found: {TRAFFIC_FILE}")

    with TRAFFIC_FILE.open("r", encoding="utf-8") as file:
        traffic = json.load(file)

    if not isinstance(traffic, list):
        raise ValueError("Traffic JSON must contain a list of packets.")

    reports = detect_port_scans(traffic)
    write_security_reports(reports)

    print(f"Packets analyzed: {len(traffic)}")
    print(f"Security reports saved: {REPORT_FILE}")

    if reports:
        for report in reports:
            print("\nTHREAT DETECTED")
            print(json.dumps(report, indent=2))
    else:
        print("No port scans detected in this capture.")


if __name__ == "__main__":
    main()
