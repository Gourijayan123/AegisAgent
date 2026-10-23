"""AegisAgent API.

Run from the ``backend`` directory::

    uvicorn main:app --port 8000

Environment variables
---------------------
AEGIS_MODE          simulate (default) | live | replay
AEGIS_IFACE         network interface for live mode (default: Scapy's default)
AEGIS_REPLAY_FILE   capture file for replay mode (default: ../data/network_traffic.json)
AEGIS_SIM_INTERVAL  seconds between simulated attacks (default: 25)
AEGIS_CORS_ORIGINS  comma-separated allowed origins
                    (default: http://localhost:5173,http://127.0.0.1:5173)
"""

from __future__ import annotations

import logging
import os
import random
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from detector import SEVERITY_ORDER, ThreatMonitor
from sources import ATTACKS, LiveCapture, Simulator, inject_attack, replay_file

log = logging.getLogger("aegis.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

MODE = os.getenv("AEGIS_MODE", "simulate").lower()
if MODE not in {"simulate", "live", "replay"}:
    raise SystemExit(f"AEGIS_MODE must be simulate, live or replay (got {MODE!r})")

DEFAULT_REPLAY = Path(__file__).resolve().parent.parent / "data" / "network_traffic.json"
REPLAY_FILE = os.getenv("AEGIS_REPLAY_FILE", str(DEFAULT_REPLAY))
SIM_INTERVAL = float(os.getenv("AEGIS_SIM_INTERVAL", "25"))
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("AEGIS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]

monitor = ThreatMonitor(source={"simulate": "simulated", "live": "live", "replay": "replay"}[MODE])
_source: Optional[Any] = None
_replay_info: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _source
    if MODE == "live":
        _source = LiveCapture(monitor, iface=os.getenv("AEGIS_IFACE") or None)
        _source.start()
        log.info("Live capture started")
    elif MODE == "simulate":
        _source = Simulator(monitor, interval=SIM_INTERVAL)
        _source.start()
        log.info("Simulator started (an attack every %.0fs)", SIM_INTERVAL)
    else:
        try:
            _replay_info["packets"] = replay_file(monitor, REPLAY_FILE)
            log.info("Replayed %s packets from %s", _replay_info["packets"], REPLAY_FILE)
        except (OSError, ValueError) as exc:
            _replay_info["error"] = str(exc)
            log.error("Replay failed: %s", exc)
    yield
    if _source is not None:
        _source.stop()


app = FastAPI(title="AegisAgent API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/api/health")
def health() -> Dict[str, Any]:
    info: Dict[str, Any] = {"status": "ok", "mode": MODE, "time": _now(), **monitor.stats()}
    error = getattr(_source, "error", None) or _replay_info.get("error")
    if error:
        info["status"] = "degraded"
        info["error"] = error
    return info


@app.get("/api/alerts/latest")
def latest_alerts(
    limit: int = Query(100, ge=1, le=500),
    min_severity: Optional[str] = Query(None, description="Low, Medium, High or Critical"),
) -> Dict[str, Any]:
    alerts = monitor.latest(500)
    if min_severity:
        wanted = min_severity.capitalize()
        if wanted not in SEVERITY_ORDER:
            raise HTTPException(status_code=422, detail=f"min_severity must be one of {SEVERITY_ORDER}")
        floor = SEVERITY_ORDER.index(wanted)
        alerts = [a for a in alerts if SEVERITY_ORDER.index(a["severity"]) >= floor]
    return {"alerts": alerts[:limit], "count": len(alerts[:limit]), "mode": MODE, "generated_at": _now()}


@app.delete("/api/alerts")
def clear_alerts() -> Dict[str, int]:
    return {"cleared": monitor.clear()}


@app.get("/api/simulate")
def list_simulations() -> Dict[str, Any]:
    return {"enabled": MODE == "simulate", "attacks": sorted(ATTACKS)}


@app.post("/api/simulate/{kind}")
def simulate_attack(kind: str) -> Dict[str, Any]:
    """Inject a synthetic attack (simulate mode only) to see it appear in the dashboard."""
    if MODE != "simulate":
        raise HTTPException(status_code=403, detail="Attack injection is only available when AEGIS_MODE=simulate")
    if kind not in ATTACKS:
        raise HTTPException(status_code=404, detail=f"Unknown attack {kind!r}; choose from {sorted(ATTACKS)}")
    return {"injected": kind, "packets": inject_attack(monitor, kind, random.Random())}
