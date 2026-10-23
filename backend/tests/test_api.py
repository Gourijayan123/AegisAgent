import os
import sys
from pathlib import Path

os.environ["AEGIS_MODE"] = "simulate"
os.environ["AEGIS_SIM_INTERVAL"] = "3600"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402


def test_alert_contract_matches_frontend():
    with TestClient(main.app) as client:
        body = client.get("/api/alerts/latest").json()
        assert isinstance(body["alerts"], list) and body["alerts"]   # simulator preloads attacks
        need = {"id", "attack_type", "source_ip", "destination_ip", "severity", "confidence",
                "status", "protocol", "packet_count", "timestamp", "evidence", "analysis", "recommendation"}
        for alert in body["alerts"]:
            assert need <= alert.keys()
            assert alert["data_source"] == "simulated"


def test_inject_filter_clear_and_cors():
    with TestClient(main.app) as client:
        assert client.delete("/api/alerts").json()["cleared"] >= 0
        assert client.get("/api/alerts/latest").json()["alerts"] == []
        assert client.post("/api/simulate/syn_flood").status_code == 200
        assert client.post("/api/simulate/nope").status_code == 404
        crit = client.get("/api/alerts/latest?min_severity=critical").json()["alerts"]
        assert crit and all(a["severity"] == "Critical" for a in crit)
        assert client.get("/api/alerts/latest?min_severity=bogus").status_code == 422
        r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert r.json()["mode"] == "simulate"
        assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
