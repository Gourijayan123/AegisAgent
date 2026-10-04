from scapy.all import *
from datetime import datetime
import json

traffic = []

print("AegisAgent Network Monitor Started")
print("Capturing 20 packets...")
print("Generate some network traffic in your browser.")

packets = sniff(count=20)

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
    "packet_size": len(packet)

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

with open("network_traffic.json", "w") as file:
    json.dump(traffic, file, indent=4)

print("Capture complete.")
print("IP packets saved:", len(traffic))
print("Output file: network_traffic.json")