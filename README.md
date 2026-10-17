## Improvements Made

### 1. Fixed Network Traffic File Path

**Problem:** The threat detector attempted to load `network_traffic.json` from the current working directory, causing a `FileNotFoundError` because the file is stored in the `data/` directory.

**Improvement:** Used Python's `pathlib.Path` to resolve the project root relative to the script and locate `data/network_traffic.json`.

**Benefit:** The detector can locate the traffic file reliably without depending on the terminal's current working directory.

**Files modified:** `detection/threat_detector.py`

