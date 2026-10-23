"""Run the detection engine over a saved capture and print the alerts.

Usage:
    python detection/threat_detector.py [data/network_traffic.json]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from detector import ThreatMonitor  # noqa: E402
from sources import replay_file  # noqa: E402


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "network_traffic.json"
    if not path.exists():
        sys.exit(f"Capture file not found: {path}")

    monitor = ThreatMonitor(source="replay")
    count = replay_file(monitor, str(path))
    alerts = list(reversed(monitor.latest(500)))

    print(f"Analysed {count} packets from {path}")
    if not alerts:
        print("Status: Normal - no threats detected")
        return
    for a in alerts:
        print(f"\n[{a['severity'].upper()}] {a['attack_type']}  {a['source_ip']} -> {a['destination_ip']}"
              f"  (confidence {a['confidence']}%, {a['packet_count']} packets)")
        for line in a["evidence"]:
            print(f"  - {line}")
        print(f"  Recommendation: {a['recommendation']}")
    print(f"\n{len(alerts)} threat(s) detected")
    sys.exit(1)


if __name__ == "__main__":
    main()
