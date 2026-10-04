import json
from collections import defaultdict

with open("network_traffic.json", "r") as file:
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