"""Detection rules that convert network traffic into security findings."""

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

PORT_SCAN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


def parse_timestamp(value):
    """Convert an ISO timestamp into a timezone-aware datetime."""
    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def find_port_scans(traffic):
    """Return one finding for each source-target pair that scans ports."""
    packets_by_host = defaultdict(list)

    for packet in traffic:
        if not isinstance(packet, dict) or packet.get("protocol") != "TCP":
            continue

        source_ip = packet.get("src_ip")
        destination_ip = packet.get("dst_ip")
        timestamp = parse_timestamp(packet.get("timestamp"))

        try:
            destination_port = int(packet.get("dst_port"))
        except (TypeError, ValueError):
            continue

        if not source_ip or not destination_ip or timestamp is None:
            continue
        if not 1 <= destination_port <= 65535:
            continue

        packets_by_host[(source_ip, destination_ip)].append(
            (timestamp, destination_port)
        )

    findings = []

    for (source_ip, destination_ip), packets in packets_by_host.items():
        packets.sort(key=lambda item: item[0])
        recent_packets = deque()
        port_counts = Counter()

        for timestamp, destination_port in packets:
            recent_packets.append((timestamp, destination_port))
            port_counts[destination_port] += 1

            while recent_packets and (
                timestamp - recent_packets[0][0]
            ).total_seconds() > TIME_WINDOW_SECONDS:
                _, expired_port = recent_packets.popleft()
                port_counts[expired_port] -= 1
                if port_counts[expired_port] == 0:
                    del port_counts[expired_port]

            if len(port_counts) >= PORT_SCAN_THRESHOLD:
                findings.append({
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "detected_at": timestamp.isoformat(),
                    "unique_destination_ports": len(port_counts),
                    "packet_count": len(recent_packets),
                    "ports": sorted(port_counts),
                })
                break

    return findings
