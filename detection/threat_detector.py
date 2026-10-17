import json
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAFFIC_FILE = PROJECT_ROOT / "data" / "network_traffic.json"

with TRAFFIC_FILE.open("r", encoding="utf-8") as file:
    traffic = json.load(file)

ports_by_source = defaultdict(set)

for packet in traffic:
    if packet["protocol"] == "TCP":
        src_ip = packet["src_ip"]
        dst_port = packet["dst_port"]

        if dst_port is not None:
            ports_by_source[src_ip].add(dst_port)

for src_ip, ports in ports_by_source.items():

    print("\nSource IP:", src_ip)
    print("Unique destination ports:", len(ports))

    if len(ports) >= 5:
        print("THREAT DETECTED: Possible Port Scan")
        print("Severity: High")
    else:
        print("Status: Normal")