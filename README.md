## Improvements Made

### 1. Fixed Network Traffic File Path

**Problem:** The threat detector attempted to load `network_traffic.json` from the current working directory, causing a `FileNotFoundError` because the file is stored in the `data/` directory.

**Improvement:** Used Python's `pathlib.Path` to resolve the project root relative to the script and locate `data/network_traffic.json`.

**Benefit:** The detector can locate the traffic file without depending on the terminal's current working directory.

**File modified:** `detection/threat_detector.py`

### 2. Improved TCP Port-Scan Detection

**Problem:** The original detector counted unique TCP destination ports by source IP across the entire capture. This could combine traffic to different target devices and did not consider when the connections occurred.

**Improvements made:**
- Grouped packets by source IP and destination IP.
- Added a configurable 60-second sliding time window.
- Counted unique destination ports instead of total packets.
- Added timestamp parsing and validation to handle missing or invalid timestamps.
- Returned structured alert dictionaries containing the source IP, destination IP, timestamp, severity, and detection evidence.
- Limited detection to one alert per source-target pair per analysis run.

**Detection rule:** Flag a possible TCP port scan when a source contacts at least five unique TCP destination ports on the same target within 60 seconds.

**Benefit:** Detection focuses on concentrated port activity against a specific target, reducing misleading results from unrelated connections.

**File modified:** `detection/threat_detector.py`

**Current limitation:** The detector analyzes a saved JSON capture and prints the resulting alerts. Continuous live-stream analysis and saving alerts to `data/alerts.json` have not yet been implemented.
