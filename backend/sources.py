"""Packet sources that feed a ``ThreatMonitor``.

* ``LiveCapture``  - real traffic via Scapy (needs root / Administrator).
* ``replay_file``  - feed a saved ``network_traffic.json`` through the detector.
* ``Simulator``    - synthetic normal traffic plus periodic attacks, for demos.
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from detector import Packet, ThreatMonitor, iso, packet_time

log = logging.getLogger("aegis.sources")


# --------------------------------------------------------------------------
# live capture
# --------------------------------------------------------------------------


def packet_to_dict(pkt: Any) -> Optional[Packet]:
    """Convert a Scapy packet to the JSON schema used across the project."""
    from scapy.all import ICMP, IP, TCP, UDP

    if IP not in pkt:
        return None

    ts = float(pkt.time)
    data: Packet = {
        "timestamp": datetime.fromtimestamp(ts).isoformat(),
        "ts": ts,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": "Other",
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "packet_size": len(pkt),
    }
    if TCP in pkt:
        data.update(
            protocol="TCP",
            src_port=int(pkt[TCP].sport),
            dst_port=int(pkt[TCP].dport),
            tcp_flags=str(pkt[TCP].flags),
        )
    elif UDP in pkt:
        data.update(protocol="UDP", src_port=int(pkt[UDP].sport), dst_port=int(pkt[UDP].dport))
    elif ICMP in pkt:
        data["protocol"] = "ICMP"
    return data


class LiveCapture(threading.Thread):
    """Sniff packets continuously and feed them to the monitor."""

    def __init__(self, monitor: ThreatMonitor, iface: Optional[str] = None) -> None:
        super().__init__(name="aegis-live-capture", daemon=True)
        self.monitor = monitor
        self.iface = iface
        self.error: Optional[str] = None
        self._stop_evt = threading.Event()

    def run(self) -> None:
        try:
            from scapy.all import sniff
        except ImportError:
            self.error = "scapy is not installed (pip install scapy)"
            log.error(self.error)
            return

        def handle(pkt: Any) -> None:
            data = packet_to_dict(pkt)
            if data:
                self.monitor.process(data)

        try:
            sniff(
                iface=self.iface,
                prn=handle,
                store=False,
                stop_filter=lambda _: self._stop_evt.is_set(),
            )
        except (PermissionError, OSError) as exc:
            self.error = (
                f"Live capture failed: {exc}. Run with root/Administrator privileges "
                "(and install Npcap on Windows)."
            )
            log.error(self.error)

    def stop(self) -> None:
        self._stop_evt.set()


# --------------------------------------------------------------------------
# replay
# --------------------------------------------------------------------------


def replay_file(monitor: ThreatMonitor, path: str) -> int:
    """Feed every packet in a capture file through the monitor; return the count."""
    with open(path, "r", encoding="utf-8") as fh:
        packets = json.load(fh)
    if not isinstance(packets, list):
        raise ValueError(f"{path} must contain a JSON list of packets")
    packets.sort(key=packet_time)
    for pkt in packets:
        if isinstance(pkt, dict):
            monitor.process(pkt)
    return len(packets)


# --------------------------------------------------------------------------
# simulator
# --------------------------------------------------------------------------

CLIENT = "192.168.1.7"
SERVER = "192.168.1.20"
PUBLIC_HOSTS = ["104.18.39.21", "142.250.77.14", "151.101.1.69", "57.144.57.32"]


def _pkt(ts: float, src: str, dst: str, proto: str = "TCP", sport: Optional[int] = None,
         dport: Optional[int] = None, flags: Optional[str] = None, size: int = 60) -> Packet:
    return {
        "timestamp": iso(ts), "ts": ts, "src_ip": src, "dst_ip": dst, "protocol": proto,
        "src_port": sport, "dst_port": dport, "tcp_flags": flags, "packet_size": size,
    }


def _attacker(rng: random.Random) -> str:
    # RFC 5737 documentation ranges: never real hosts.
    return f"{rng.choice(['203.0.113', '198.51.100'])}.{rng.randint(2, 250)}"


def normal_traffic(end: float, rng: random.Random, n: int = 8) -> List[Packet]:
    out: List[Packet] = []
    for i in range(n):
        host = rng.choice(PUBLIC_HOSTS)
        sport = rng.randint(49152, 65000)
        ts = end - (n - i) * 0.05
        if rng.random() < 0.25:
            out.append(_pkt(ts, CLIENT, "8.8.8.8", "UDP", sport, 53, None, rng.randint(70, 120)))
        else:
            out.append(_pkt(ts, CLIENT, host, "TCP", sport, 443, "PA", rng.randint(60, 1400)))
            out.append(_pkt(ts + 0.01, host, CLIENT, "TCP", 443, sport, "A", 54))
    return out


def sim_port_scan(end: float, rng: random.Random) -> List[Packet]:
    src, ports, gap = _attacker(rng), rng.sample(range(1, 1024), 40), 0.05
    return [_pkt(end - (40 - i) * gap, src, SERVER, "TCP", rng.randint(40000, 60000), p, "S", 60)
            for i, p in enumerate(ports)]


def sim_sweep(end: float, rng: random.Random) -> List[Packet]:
    src, gap = _attacker(rng), 0.1
    return [_pkt(end - (30 - i) * gap, src, f"192.168.1.{i + 1}", "TCP", rng.randint(40000, 60000), 445, "S", 60)
            for i in range(30)]


def sim_syn_flood(end: float, rng: random.Random) -> List[Packet]:
    src, gap = _attacker(rng), 0.01
    return [_pkt(end - (150 - i) * gap, src, SERVER, "TCP", rng.randint(1024, 65000), 80, "S", 60)
            for i in range(150)]


def sim_brute_force(end: float, rng: random.Random) -> List[Packet]:
    src, port, gap = _attacker(rng), rng.choice([22, 3389, 21]), 0.5
    return [_pkt(end - (25 - i) * gap, src, SERVER, "TCP", rng.randint(40000, 60000), port, "S", 60)
            for i in range(25)]


def sim_icmp_flood(end: float, rng: random.Random) -> List[Packet]:
    src, gap = _attacker(rng), 0.02
    return [_pkt(end - (80 - i) * gap, src, "192.168.1.1", "ICMP", size=98) for i in range(80)]


def sim_suspicious_port(end: float, rng: random.Random) -> List[Packet]:
    host = f"192.168.1.{rng.randint(40, 90)}"
    return [_pkt(end - (3 - i) * 0.2, host, "185.220.101.4", "TCP", rng.randint(40000, 60000), 4444, "PA", 200)
            for i in range(3)]


def sim_exfiltration(end: float, rng: random.Random) -> List[Packet]:
    host = f"192.168.1.{rng.randint(91, 120)}"
    return [_pkt(end - (100 - i) * 0.1, host, "45.33.32.156", "TCP", 50123, 443, "PA", 60000)
            for i in range(100)]


ATTACKS: Dict[str, Callable[[float, random.Random], List[Packet]]] = {
    "port_scan": sim_port_scan,
    "network_sweep": sim_sweep,
    "syn_flood": sim_syn_flood,
    "brute_force": sim_brute_force,
    "icmp_flood": sim_icmp_flood,
    "suspicious_port": sim_suspicious_port,
    "exfiltration": sim_exfiltration,
}


def inject_attack(monitor: ThreatMonitor, kind: str, rng: Optional[random.Random] = None) -> int:
    """Feed one synthetic attack into the monitor; return packets injected."""
    if kind not in ATTACKS:
        raise KeyError(kind)
    packets = ATTACKS[kind](time.time(), rng or random.Random())
    for pkt in packets:
        monitor.process(pkt)
    return len(packets)


class Simulator(threading.Thread):
    """Background traffic generator: steady normal traffic plus periodic attacks."""

    def __init__(self, monitor: ThreatMonitor, interval: float = 25.0, preload: int = 3) -> None:
        super().__init__(name="aegis-simulator", daemon=True)
        self.monitor = monitor
        self.interval = interval
        self.preload = preload
        self.rng = random.Random()
        self._stop_evt = threading.Event()

    def run(self) -> None:
        kinds = list(ATTACKS)
        order = self.rng.sample(kinds, len(kinds))
        idx = 0

        for _ in range(self.preload):
            inject_attack(self.monitor, order[idx % len(order)], self.rng)
            idx += 1

        next_attack = time.time() + self.interval
        while not self._stop_evt.wait(1.0):
            now = time.time()
            for pkt in normal_traffic(now, self.rng):
                self.monitor.process(pkt)
            if now >= next_attack:
                inject_attack(self.monitor, order[idx % len(order)], self.rng)
                idx += 1
                next_attack = now + self.interval

    def stop(self) -> None:
        self._stop_evt.set()
