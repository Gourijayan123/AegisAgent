# AegisAgent

Network threat detection with a live dashboard.

```
packets ──► detector (sliding-window rules) ──► FastAPI /api/alerts/latest ──► React dashboard
 (live / replay / simulated)      backend/detector.py        backend/main.py              frontend/
```

## Quick start (demo, no root needed)

```bash
# 1. backend  (http://localhost:8000)
cd backend
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --port 8000

# 2. frontend (http://localhost:5173) - in a second terminal
cd frontend
npm install
npm run dev
```

The sidebar shows **Connected - Simulated traffic (demo backend)**. The simulator generates
normal traffic plus an attack every ~25 s; alerts appear within 5 s. Trigger one on demand:

```bash
curl -X POST localhost:8000/api/simulate/port_scan
# port_scan  network_sweep  syn_flood  brute_force  icmp_flood  suspicious_port  exfiltration
```

## Modes (`AEGIS_MODE`)

| Mode | What it does |
|------|--------------|
| `simulate` (default) | Synthetic traffic + attacks. Safe demo; alerts are labelled `data_source: simulated`. |
| `live` | Sniffs real packets with Scapy. Needs root/Administrator (Npcap on Windows). `sudo AEGIS_MODE=live venv/bin/uvicorn main:app` |
| `replay` | Runs a saved capture (`AEGIS_REPLAY_FILE`, default `data/network_traffic.json`) through the detector once. |

Other variables: `AEGIS_IFACE`, `AEGIS_SIM_INTERVAL`, `AEGIS_CORS_ORIGINS`. The frontend reads
`VITE_API_URL` (default `http://localhost:8000`).

## What it detects

| Alert | Rule (defaults in `DetectorConfig`) |
|-------|-------------------------------------|
| Port Scan | SYN-only packets from one source to >= 15 ports of one host within 10 s |
| Network Sweep | SYN-only packets to one port on >= 10 hosts within 10 s |
| SYN Flood | >= 100 SYN-only packets at one host within 5 s (any number of sources) |
| SSH/RDP/FTP/Telnet/SMB/VNC Brute Force | >= 10 SYNs from one source to a login port within 60 s |
| ICMP Flood | >= 50 ICMP packets from one source to one host within 5 s |
| Suspicious Port Activity | Internal host connecting out to a known backdoor/C2 port |
| Data Exfiltration | >= 5 MB from an internal to an external host within 60 s |

Severity rises one level when activity is >= 3x the threshold. Repeat packets from the same
attack update one alert (60 s cool-down) instead of creating hundreds. Tune thresholds for
your network: a busy web server legitimately receives many SYNs, so raise `syn_flood_count` there.

## API

* `GET /api/alerts/latest?limit=100&min_severity=High`
* `GET /api/health` - mode, packets seen, alert counts, capture errors
* `DELETE /api/alerts` - clear stored alerts
* `GET /api/simulate`, `POST /api/simulate/{kind}` - simulate mode only

## Command-line tools

```bash
python detection/threat_detector.py [capture.json]   # analyse a saved capture (exit code 1 if threats)
sudo python detection/network_monitor.py --count 500 # record a capture to data/network_traffic.json
```

## Tests

```bash
cd backend && python -m pytest
```

## Limitations

* The dashboard's traffic charts, top talkers, device scan and AI chat are still demo data;
  only alerts come from the backend. Alert status changes, notes and the blocklist live in the
  browser session only and do not block anything.
* Detection is rule-based and IPv4-only. There is no authentication on the API, so keep it on
  localhost or behind a reverse proxy.
* Only scan or monitor networks you own or are authorised to test.
