
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, deque, Counter

# EXISTING IMPROVEMENT:
# Resolve the traffic file relative to the project directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAFFIC_FILE = PROJECT_ROOT / "data" / "network_traffic.json"

# NEW: Configure the detection rule.
# A possible scan is flagged when at least 5 unique ports
# are contacted on the same target within 60 seconds.
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


def parse_timestamp(value):
    """Convert an ISO timestamp into a timezone-aware datetime."""
    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        # NEW: Treat timestamps without timezone information as UTC.
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError):
        # NEW: Skip packets whose timestamps cannot be parsed.
        return None


def detect_port_scans(traffic):
    """Detect possible TCP port scans within a sliding time window."""

    # NEW: Keep traffic for each source-target pair separate.
    packets_by_host = defaultdict(list)

    for packet in traffic:
        if not isinstance(packet, dict):
            continue

        if packet.get("protocol") != "TCP":
            continue

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        timestamp = parse_timestamp(packet.get("timestamp"))

        # NEW: Ignore incomplete or invalid packet records.
        if not src_ip or not dst_ip or timestamp is None:
            continue

        try:
            dst_port = int(dst_port)
        except (ValueError, TypeError):
            continue

        if not 1 <= dst_port <= 65535:
            continue

        packets_by_host[(src_ip, dst_ip)].append(
            (timestamp, dst_port)
        )

    alerts = []

    # NEW: Analyze each source-target pair independently.
    for (src_ip, dst_ip), packets in packets_by_host.items():
        packets.sort(key=lambda item: item[0])

        # NEW: Store packets that are still inside the time window.
        recent_packets = deque()
        port_counts = Counter()
        alert_created = False

        for timestamp, dst_port in packets:
            recent_packets.append((timestamp, dst_port))
            port_counts[dst_port] += 1

            # NEW: Remove packets older than 60 seconds.
            while recent_packets and (
                timestamp - recent_packets[0][0]
            ).total_seconds() > TIME_WINDOW_SECONDS:
                _, old_port = recent_packets.popleft()
                port_counts[old_port] -= 1

                if port_counts[old_port] == 0:
                    del port_counts[old_port]

            # NEW: Count unique ports, not total packets.
            if len(port_counts) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "alert_type": "Possible TCP Port Scan",
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "severity": "Medium",
                    "timestamp": timestamp.isoformat(),
                    "evidence": {
                        "unique_destination_ports": len(port_counts),
                        "ports": sorted(port_counts.keys()),
                        "threshold": PORT_SCAN_THRESHOLD,
                        "time_window_seconds": TIME_WINDOW_SECONDS,
                    },
                })

                # NEW: Produce at most one alert per source-target
                # pair for this analysis run.
                alert_created = True
                break

    return alerts


def main():
    # EXISTING IMPROVEMENT: Use the resolved file path.
    if not TRAFFIC_FILE.exists():
        raise FileNotFoundError(
            f"Traffic file not found: {TRAFFIC_FILE}"
        )

    with TRAFFIC_FILE.open("r", encoding="utf-8") as file:
        traffic = json.load(file)

    if not isinstance(traffic, list):
        raise ValueError("Traffic JSON must contain a list of packets.")

    alerts = detect_port_scans(traffic)

    print(f"Packets analyzed: {len(traffic)}")

    if alerts:
        for alert in alerts:
            print("\nTHREAT DETECTED")
            print(json.dumps(alert, indent=2))
    else:
        print("No port scans detected in this capture.")


if __name__ == "__main__":
    main()
