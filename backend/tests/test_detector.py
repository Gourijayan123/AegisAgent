import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector import DetectorConfig, ThreatDetector, ThreatMonitor  # noqa: E402
from sources import ATTACKS, replay_file  # noqa: E402
import random  # noqa: E402

T0 = 1_800_000_000.0
SAMPLE = Path(__file__).resolve().parents[2] / "data" / "network_traffic.json"


def pkt(ts, src, dst, dport=80, proto="TCP", flags="S", size=60):
    return {"ts": ts, "src_ip": src, "dst_ip": dst, "protocol": proto,
            "src_port": 50000, "dst_port": dport, "tcp_flags": flags, "packet_size": size}


def run(packets):
    det = ThreatDetector()
    alerts = []
    for p in packets:
        alerts += det.ingest(p)
    return alerts


def test_busy_normal_client_is_not_flagged():
    # 200 completed connections to 30 different ports over an hour (PA/A flags, spread out)
    packets = [pkt(T0 + i * 18, "192.168.1.7", "93.184.216.34", 1000 + i % 30, flags="PA") for i in range(200)]
    assert run(packets) == []


def test_slow_syn_activity_is_not_a_scan():
    # 20 distinct ports but one every 5s -> never 15 inside a 10s window
    packets = [pkt(T0 + i * 5, "203.0.113.9", "192.168.1.20", 100 + i) for i in range(20)]
    assert run(packets) == []


def test_port_scan_detected_once():
    packets = [pkt(T0 + i * 0.05, "203.0.113.9", "192.168.1.20", 100 + i) for i in range(60)]
    alerts = run(packets)
    scans = [a for a in alerts if a["attack_type"] == "Port Scan"]
    assert len(scans) == 1                      # cooldown: one alert, not one per packet
    a = scans[0]
    assert a["source_ip"] == "203.0.113.9" and a["destination_ip"] == "192.168.1.20"
    assert a["severity"] in {"High", "Critical"} and 70 <= a["confidence"] <= 99
    assert a["packet_count"] >= 15 and a["evidence"] and a["recommendation"]


def test_scan_alert_keeps_growing_while_attack_continues():
    det = ThreatDetector()
    first = None
    for i in range(80):
        for a in det.ingest(pkt(T0 + i * 0.05, "203.0.113.9", "192.168.1.20", 100 + i)):
            first = a
    assert first["packet_count"] >= 60 and first["severity"] == "Critical"


def test_new_scan_after_cooldown_is_a_new_alert():
    a1 = run([pkt(T0 + i * 0.05, "203.0.113.9", "192.168.1.20", 100 + i) for i in range(30)])
    det = ThreatDetector()
    alerts = []
    for base in (T0, T0 + 300):
        for i in range(30):
            alerts += det.ingest(pkt(base + i * 0.05, "203.0.113.9", "192.168.1.20", 100 + i))
    assert len(a1) == 1 and len([a for a in alerts if a["attack_type"] == "Port Scan"]) == 2


def test_network_sweep():
    packets = [pkt(T0 + i * 0.1, "203.0.113.9", f"192.168.1.{i + 1}", 445) for i in range(20)]
    assert any(a["attack_type"] == "Network Sweep" for a in run(packets))


def test_syn_flood_from_many_sources():
    packets = [pkt(T0 + i * 0.01, f"198.51.100.{i % 50 + 1}", "192.168.1.20", 80) for i in range(150)]
    alerts = [a for a in run(packets) if a["attack_type"] == "SYN Flood"]
    assert len(alerts) == 1 and alerts[0]["severity"] == "Critical"


def test_ssh_brute_force():
    packets = [pkt(T0 + i * 0.5, "198.51.100.23", "192.168.1.20", 22) for i in range(15)]
    alerts = [a for a in run(packets) if a["attack_type"] == "SSH Brute Force"]
    assert len(alerts) == 1


def test_established_ssh_session_is_not_brute_force():
    packets = [pkt(T0 + i, "192.168.1.7", "192.168.1.20", 22, flags="PA") for i in range(100)]
    assert run(packets) == []


def test_icmp_flood():
    packets = [pkt(T0 + i * 0.02, "203.0.113.5", "192.168.1.1", None, "ICMP", None, 98) for i in range(60)]
    assert any(a["attack_type"] == "ICMP Flood" for a in run(packets))


def test_suspicious_port_only_for_internal_to_external():
    out = run([pkt(T0, "192.168.1.15", "185.220.101.4", 4444, flags="PA")])
    assert [a["attack_type"] for a in out] == ["Suspicious Port Activity"]
    assert run([pkt(T0, "203.0.113.5", "192.168.1.15", 4444, flags="PA")]) == []


def test_exfiltration():
    packets = [pkt(T0 + i * 0.1, "192.168.1.30", "45.33.32.156", 443, flags="PA", size=60000) for i in range(100)]
    assert any(a["attack_type"] == "Data Exfiltration" for a in run(packets))


def test_malformed_packets_do_not_crash():
    det = ThreatDetector()
    for bad in ({}, {"src_ip": "1.1.1.1"}, {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "packet_size": "x"},
                {"src_ip": "x", "dst_ip": "y", "protocol": "TCP", "tcp_flags": "S", "dst_port": 22}):
        det.ingest(bad)


def test_every_simulated_attack_is_detected():
    for kind in ATTACKS:
        mon = ThreatMonitor(source="test")
        for p in ATTACKS[kind](T0, random.Random(1)):
            mon.process(p)
        assert mon.latest(), f"{kind} produced no alert"


def test_committed_sample_capture_has_no_threats():
    mon = ThreatMonitor(source="replay")
    assert replay_file(mon, str(SAMPLE)) > 0
    assert mon.latest() == []


def test_window_state_is_garbage_collected():
    det = ThreatDetector(DetectorConfig(gc_every=100))
    for i in range(1000):
        det.ingest(pkt(T0 + i * 100, f"10.0.{i // 250}.{i % 250}", "192.168.1.20", 80))
    assert len(det._scan) < 10
