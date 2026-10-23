"""Capture packets with Scapy and save them as JSON.

Usage (needs root / Administrator):
    python detection/network_monitor.py [--count 200] [--timeout 30] [--iface eth0] [--out data/network_traffic.json]

For continuous detection with the dashboard, run the API in live mode instead:
    AEGIS_MODE=live uvicorn main:app   (from the backend/ directory)
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sources import packet_to_dict  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", type=int, default=200, help="stop after this many packets")
    parser.add_argument("--timeout", type=float, default=30, help="stop after this many seconds")
    parser.add_argument("--iface", default=None, help="network interface (default: Scapy's default)")
    parser.add_argument("--out", default=str(ROOT / "data" / "network_traffic.json"))
    args = parser.parse_args()

    from scapy.all import sniff

    print(f"AegisAgent capture: up to {args.count} packets / {args.timeout:.0f}s ...")
    try:
        packets = sniff(count=args.count, timeout=args.timeout, iface=args.iface, store=True)
    except PermissionError:
        sys.exit("Permission denied: run as root/Administrator (and install Npcap on Windows).")

    traffic = [d for d in map(packet_to_dict, packets) if d]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(traffic, indent=2), encoding="utf-8")
    print(f"Saved {len(traffic)} IP packets to {out}")


if __name__ == "__main__":
    main()
