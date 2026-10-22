# AegisAgent

AegisAgent captures network traffic, detects potential TCP port scans, and
creates structured security reports for AI-assisted investigation.

## Setup

Install the Python dependency:

```bash
python -m pip install -r requirements.txt
```

On Windows, install [Npcap](https://npcap.com/) and run the network monitor
from an elevated terminal so Scapy can capture packets.

## Workflow

1. Capture traffic:

   ```bash
   python detection/network_monitor.py
   ```

   The monitor captures 20 packets and saves IP traffic to
   `data/network_traffic.json`.

2. Detect threats and generate reports:

   ```bash
   python detection/threat_detector.py
   ```

   The detector reads the traffic capture and writes AI-ready reports to
   `data/security_reports.json`.

## Detection Rule

A potential TCP port scan is detected when one source IP contacts at least
five unique destination ports on the same destination IP within 60 seconds.
Each source-target pair produces at most one report per analysis run.

## Security Report Format

```json
{
  "source_ip": "192.168.1.20",
  "threat_category": "Port Scan",
  "severity": "High",
  "evidence": [
    "Multiple destination ports contacted",
    "High connection frequency"
  ],
  "threat_intelligence": {
    "reputation": "Unknown"
  },
  "recommended_investigation": [
    "Review connection history",
    "Check destination host activity"
  ]
}
```

Threat intelligence currently uses the offline `Unknown` fallback. Connect a
reputation provider in `detection/threat_intelligence.py` when one is available.

## Detection Modules

- `detection/network_monitor.py` captures packet data with Scapy.
- `detection/security_rules.py` identifies port-scan findings.
- `detection/severity.py` assigns report severity.
- `detection/threat_intelligence.py` enriches IP reputation data.
- `detection/cybersecurity_context.py` builds AI-ready reports.
- `detection/threat_detector.py` coordinates detection and report output.

## Tests

Run the detection tests with:

```bash
python -m unittest discover -s detection -p "test*.py" -v
```
