from datetime import datetime
from pathlib import Path
import json
import sys

try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff
except ImportError:
    print("Scapy is required to capture network traffic.", file=sys.stderr)
    print("Install it with: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(1)

traffic = []

print("AegisAgent Network Monitor Started")
print("Capturing 20 packets...")
print("Generate some network traffic in your browser.")

try:
    packets = sniff(count=20)
except Exception as error:
    print(f"Unable to capture network traffic: {error}", file=sys.stderr)
    if sys.platform == "win32":
        print("On Windows, install Npcap and run this script from an elevated terminal.", file=sys.stderr)
    else:
        print("Run this script with permission to capture network packets.", file=sys.stderr)
    raise SystemExit(1)

# Resolve output path relative to the script so the file always lands in
# data/network_traffic.json regardless of the working directory.
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "data" / "network_traffic.json"

for packet in packets:

    if IP not in packet:
        continue

    data = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "Other",
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "packet_size": len(packet),
    }

    if TCP in packet:
        data["protocol"] = "TCP"
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport
        data["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        data["protocol"] = "UDP"
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        data["protocol"] = "ICMP"

    traffic.append(data)

with open(OUTPUT_FILE, "w") as file:
    json.dump(traffic, file, indent=4)

print("Capture complete.")
print("IP packets saved:", len(traffic))
print(f"Output file: {OUTPUT_FILE}")
