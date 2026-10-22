"""Build AI-ready investigation reports from security findings."""

from severity import classify_port_scan
from threat_intelligence import lookup_ip_reputation


def build_port_scan_report(finding):
    """Create the public report schema for a detected port scan."""
    return {
        "source_ip": finding["source_ip"],
        "threat_category": "Port Scan",
        "severity": classify_port_scan(finding["unique_destination_ports"]),
        "evidence": [
            "Multiple destination ports contacted",
            "High connection frequency",
        ],
        "threat_intelligence": lookup_ip_reputation(finding["source_ip"]),
        "recommended_investigation": [
            "Review connection history",
            "Check destination host activity",
        ],
    }
