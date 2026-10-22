"""Severity classification for security findings."""


def classify_port_scan(unique_destination_ports):
    """Return a consistent severity for a confirmed port scan."""
    if unique_destination_ports >= 20:
        return "Critical"
    if unique_destination_ports >= 5:
        return "High"
    return "Medium"
