"""AegisAgent threat-detection engine.

Consumes packet records (the same schema the capture script writes to
``data/network_traffic.json``) one at a time and emits alerts when traffic
matches a rule.  All rules use sliding time windows, so a busy-but-normal
host is not flagged just because it has talked to many ports over a long
capture.

Packet schema (dict)::

    {"timestamp": ISO-8601 str, "ts": epoch float (optional, preferred),
     "src_ip": str, "dst_ip": str, "protocol": "TCP"|"UDP"|"ICMP"|"Other",
     "src_port": int|None, "dst_port": int|None,
     "tcp_flags": str|None  (scapy style: "S", "SA", "PA", ...),
     "packet_size": int}

Rules
-----
* Port Scan            - one source, SYN-only packets to many ports of one host
* Network Sweep        - one source, SYN-only packets to one port on many hosts
* SYN Flood            - many SYN-only packets at one host (any number of sources)
* <Service> Brute Force- repeated SYNs from one source to a login service port
* ICMP Flood           - many ICMP packets from one source to one host
* Suspicious Port Activity - internal host talking to a known backdoor/C2 port
* Data Exfiltration    - large volume from an internal host to an external one
"""

from __future__ import annotations

import copy
import ipaddress
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable, Deque, Dict, Hashable, List, Optional, Tuple

Packet = Dict[str, Any]
Alert = Dict[str, Any]

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

BRUTE_FORCE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}

SUSPICIOUS_PORTS = {
    1337: "a common backdoor port",
    4444: "the Metasploit default listener port",
    6667: "IRC, often used for botnet command and control",
    12345: "the NetBus trojan port",
    31337: "the Back Orifice trojan port",
}


@dataclass
class DetectorConfig:
    """Thresholds. Tune these for the network being monitored."""

    port_scan_ports: int = 15        # distinct ports on one host ...
    port_scan_window: float = 10.0   # ... within this many seconds
    sweep_hosts: int = 10            # distinct hosts on one port ...
    sweep_window: float = 10.0
    syn_flood_count: int = 100       # SYN-only packets at one host ...
    syn_flood_window: float = 5.0
    brute_attempts: int = 10         # SYNs from one source to one login port ...
    brute_window: float = 60.0
    icmp_flood_count: int = 50
    icmp_flood_window: float = 5.0
    exfil_bytes: int = 5_000_000     # bytes internal -> external ...
    exfil_window: float = 60.0
    alert_cooldown: float = 60.0     # keep updating one alert while activity continues
    gc_every: int = 2000             # packets between state clean-ups


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
]


@lru_cache(maxsize=8192)
def is_internal(ip: str) -> bool:
    """True for RFC1918 / loopback / link-local addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6:
        return addr.is_loopback or addr.is_link_local or addr.is_private
    return any(addr in net for net in _INTERNAL_NETS)


@lru_cache(maxsize=8192)
def is_external_target(ip: str) -> bool:
    """True for a routable-looking destination outside the local network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if is_internal(ip) or addr.is_multicast or addr.is_unspecified:
        return False
    return str(addr) != "255.255.255.255"


def packet_time(pkt: Packet) -> float:
    """Epoch seconds for a packet (``ts`` if present, else parsed ``timestamp``)."""
    ts = pkt.get("ts")
    if isinstance(ts, (int, float)):
        return float(ts)
    raw = pkt.get("timestamp")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw).timestamp()
        except ValueError:
            pass
    return time.time()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class _Window:
    """Sliding window of (timestamp, value, weight) with O(1) distinct/total."""

    __slots__ = ("items", "counts", "total")

    def __init__(self) -> None:
        self.items: Deque[Tuple[float, Hashable, int]] = deque()
        self.counts: Dict[Hashable, int] = {}
        self.total = 0

    def add(self, ts: float, value: Hashable, horizon: float, weight: int = 1) -> None:
        self.items.append((ts, value, weight))
        self.counts[value] = self.counts.get(value, 0) + weight
        self.total += weight
        self.prune(ts, horizon)

    def prune(self, now: float, horizon: float) -> None:
        cutoff = now - horizon
        items = self.items
        while items and items[0][0] < cutoff:
            _, value, weight = items.popleft()
            remaining = self.counts.get(value, 0) - weight
            if remaining <= 0:
                self.counts.pop(value, None)
            else:
                self.counts[value] = remaining
            self.total -= weight

    @property
    def packets(self) -> int:
        return len(self.items)

    @property
    def distinct(self) -> int:
        return len(self.counts)

    def top(self) -> Hashable:
        return max(self.counts, key=self.counts.get)


def _bump(severity: str, ratio: float) -> str:
    """Escalate one level when activity is >= 3x the threshold."""
    if ratio >= 3 and severity != "Critical":
        return SEVERITY_ORDER[SEVERITY_ORDER.index(severity) + 1]
    return severity


def _confidence(ratio: float) -> int:
    return int(max(70, min(99, 75 + 12 * (ratio - 1))))


def _fmt_bytes(n: int) -> str:
    return f"{n / 1_000_000:.1f} MB"


# --------------------------------------------------------------------------
# detector
# --------------------------------------------------------------------------

Builder = Callable[[], Tuple[List[str], str, str]]


class ThreatDetector:
    """Stateful, single-threaded detector. Wrap with ``ThreatMonitor`` for threads."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.cfg = config or DetectorConfig()
        self.packets_seen = 0
        self._seq = 0
        self._scan: Dict[Hashable, _Window] = {}
        self._sweep: Dict[Hashable, _Window] = {}
        self._flood: Dict[Hashable, _Window] = {}
        self._brute: Dict[Hashable, _Window] = {}
        self._icmp: Dict[Hashable, _Window] = {}
        self._exfil: Dict[Hashable, _Window] = {}
        self._active: Dict[Hashable, Tuple[Alert, float]] = {}
        self._last_rebuild: Dict[Hashable, int] = {}

    # -- public ----------------------------------------------------------

    def ingest(self, pkt: Packet) -> List[Alert]:
        """Process one packet; return alerts that are *new* (updates are in place)."""
        self.packets_seen += 1
        src, dst = pkt.get("src_ip"), pkt.get("dst_ip")
        if not src or not dst:
            return []

        ts = packet_time(pkt)
        if self.packets_seen % self.cfg.gc_every == 0:
            self._gc(ts)

        proto = str(pkt.get("protocol") or "")
        dport = pkt.get("dst_port")
        try:
            size = max(0, int(pkt.get("packet_size") or 0))
        except (TypeError, ValueError):
            size = 0

        found: List[Optional[Alert]] = []

        if proto == "TCP":
            flags = str(pkt.get("tcp_flags") or "")
            if "S" in flags and "A" not in flags and dport is not None:
                found.append(self._check_port_scan(ts, src, dst, dport))
                found.append(self._check_sweep(ts, src, dst, dport))
                found.append(self._check_syn_flood(ts, src, dst))
                if dport in BRUTE_FORCE_PORTS:
                    found.append(self._check_brute_force(ts, src, dst, dport))
        elif proto == "ICMP":
            found.append(self._check_icmp_flood(ts, src, dst))

        if dport in SUSPICIOUS_PORTS and is_internal(src) and is_external_target(dst):
            found.append(self._check_suspicious_port(ts, src, dst, dport))

        if size and is_internal(src) and is_external_target(dst):
            found.append(self._check_exfil(ts, src, dst, size))

        return [a for a in found if a is not None]

    # -- rules -------------------------------------------------------------

    def _window(self, table: Dict[Hashable, _Window], key: Hashable) -> _Window:
        win = table.get(key)
        if win is None:
            win = table[key] = _Window()
        return win

    def _check_port_scan(self, ts: float, src: str, dst: str, dport: int) -> Optional[Alert]:
        cfg = self.cfg
        win = self._window(self._scan, (src, dst))
        win.add(ts, dport, cfg.port_scan_window)
        if win.distinct < cfg.port_scan_ports:
            return None

        def build() -> Tuple[List[str], str, str]:
            ports = sorted(win.counts)
            sample = ", ".join(str(p) for p in ports[:12]) + (" ..." if len(ports) > 12 else "")
            return (
                [
                    f"{win.distinct} distinct TCP ports probed within {cfg.port_scan_window:.0f}s",
                    f"{win.packets} SYN packets with no completed handshake",
                    f"Ports probed: {sample}",
                ],
                f"{src} sent SYN-only packets to {win.distinct} different ports on {dst} in a short "
                "window. Sequential or wide port probing like this is typical of reconnaissance "
                "tools such as nmap.",
                "Block or rate-limit the source at the firewall, confirm which of the probed ports "
                "are exposed on the target, and watch for follow-up connections from the same address.",
            )

        return self._raise(
            ("port_scan", src, dst), "Port Scan", src, dst, ts,
            base="High", ratio=win.distinct / cfg.port_scan_ports,
            protocol="TCP", packets=win.packets, build=build,
        )

    def _check_sweep(self, ts: float, src: str, dst: str, dport: int) -> Optional[Alert]:
        cfg = self.cfg
        win = self._window(self._sweep, (src, dport))
        win.add(ts, dst, cfg.sweep_window)
        if win.distinct < cfg.sweep_hosts:
            return None

        def build() -> Tuple[List[str], str, str]:
            hosts = sorted(win.counts)
            sample = ", ".join(hosts[:6]) + (" ..." if len(hosts) > 6 else "")
            return (
                [
                    f"{win.distinct} distinct hosts probed on TCP port {dport} within {cfg.sweep_window:.0f}s",
                    f"{win.packets} SYN packets with no completed handshake",
                    f"Hosts probed: {sample}",
                ],
                f"{src} is probing port {dport} across {win.distinct} hosts. A one-port, many-host "
                "pattern usually means a worm or attacker is searching for machines running a "
                "specific service.",
                f"Block the source, check which internal hosts answer on port {dport}, and patch or "
                "close the service where it is not needed.",
            )

        return self._raise(
            ("sweep", src, dport), "Network Sweep", src, "Multiple hosts", ts,
            base="High", ratio=win.distinct / cfg.sweep_hosts,
            protocol="TCP", packets=win.packets, build=build,
        )

    def _check_syn_flood(self, ts: float, src: str, dst: str) -> Optional[Alert]:
        cfg = self.cfg
        win = self._window(self._flood, dst)
        win.add(ts, src, cfg.syn_flood_window)
        if win.packets < cfg.syn_flood_count:
            return None

        def build() -> Tuple[List[str], str, str]:
            top = win.top()
            return (
                [
                    f"{win.packets} SYN-only packets at {dst} within {cfg.syn_flood_window:.0f}s",
                    f"{win.distinct} distinct source address(es); heaviest sender: {top}",
                    "Handshakes are not being completed (no ACK follow-up)",
                ],
                f"{dst} is receiving SYN packets far faster than normal clients would send them. "
                "This exhausts connection tables and is the signature of a SYN flood denial-of-service attack.",
                "Enable SYN cookies, rate-limit new connections at the edge, and block the heaviest "
                "sources. If sources are spoofed, ask the upstream provider to filter.",
            )

        top_src = win.top()
        return self._raise(
            ("syn_flood", dst), "SYN Flood", str(top_src), dst, ts,
            base="Critical", ratio=win.packets / cfg.syn_flood_count,
            protocol="TCP", packets=win.packets, build=build,
        )

    def _check_brute_force(self, ts: float, src: str, dst: str, dport: int) -> Optional[Alert]:
        cfg = self.cfg
        win = self._window(self._brute, (src, dst, dport))
        win.add(ts, dport, cfg.brute_window)
        if win.packets < cfg.brute_attempts:
            return None
        service = BRUTE_FORCE_PORTS[dport]

        def build() -> Tuple[List[str], str, str]:
            return (
                [
                    f"{win.packets} connection attempts to {service} (port {dport}) within {cfg.brute_window:.0f}s",
                    "Repeated short-lived connections from a single source",
                ],
                f"{src} opened {win.packets} connections to the {service} service on {dst} in under a "
                f"minute. Automated login guessing against {service} produces exactly this pattern.",
                f"Block the source, require key-based or multi-factor authentication for {service}, "
                "enable account lockout or fail2ban, and review logs for successful logins from this address.",
            )

        return self._raise(
            ("brute", src, dst, dport), f"{service} Brute Force", src, dst, ts,
            base="High", ratio=win.packets / cfg.brute_attempts,
            protocol="TCP", packets=win.packets, build=build,
        )

    def _check_icmp_flood(self, ts: float, src: str, dst: str) -> Optional[Alert]:
        cfg = self.cfg
        win = self._window(self._icmp, (src, dst))
        win.add(ts, dst, cfg.icmp_flood_window)
        if win.packets < cfg.icmp_flood_count:
            return None

        def build() -> Tuple[List[str], str, str]:
            return (
                [f"{win.packets} ICMP packets from {src} to {dst} within {cfg.icmp_flood_window:.0f}s"],
                f"{src} is sending ICMP traffic to {dst} at a rate consistent with a ping flood, "
                "which can saturate bandwidth or exhaust the target's resources.",
                "Rate-limit ICMP at the firewall, block the source, and check whether the target "
                "needs to answer pings from outside at all.",
            )

        return self._raise(
            ("icmp", src, dst), "ICMP Flood", src, dst, ts,
            base="Medium", ratio=win.packets / cfg.icmp_flood_count,
            protocol="ICMP", packets=win.packets, build=build,
        )

    def _check_suspicious_port(self, ts: float, src: str, dst: str, dport: int) -> Optional[Alert]:
        meaning = SUSPICIOUS_PORTS[dport]
        key = ("suspicious", src, dst, dport)
        existing = self._active.get(key)
        packets = (existing[0]["packet_count"] + 1) if existing else 1

        def build() -> Tuple[List[str], str, str]:
            return (
                [f"Outbound traffic to {dst}:{dport}, {meaning}", "Destination is outside the local network"],
                f"Internal host {src} is communicating with {dst} on port {dport}, {meaning}. "
                "Legitimate software rarely uses this port, so the host may be compromised.",
                f"Isolate {src}, inspect it for malware, and review what else it has connected to.",
            )

        return self._raise(
            key, "Suspicious Port Activity", src, dst, ts,
            base="Medium", ratio=1.0, protocol="TCP", packets=packets, build=build,
        )

    def _check_exfil(self, ts: float, src: str, dst: str, size: int) -> Optional[Alert]:
        cfg = self.cfg
        win = self._window(self._exfil, (src, dst))
        win.add(ts, dst, cfg.exfil_window, weight=size)
        if win.total < cfg.exfil_bytes:
            return None

        def build() -> Tuple[List[str], str, str]:
            return (
                [
                    f"{_fmt_bytes(win.total)} sent from {src} to {dst} within {cfg.exfil_window:.0f}s",
                    f"{win.packets} packets in the window",
                    "Destination is outside the local network",
                ],
                f"Internal host {src} pushed {_fmt_bytes(win.total)} to an external address in under "
                "a minute. Unexpected bulk uploads can indicate data theft or a compromised machine.",
                f"Confirm whether {src} should be uploading to {dst}. If not, cut the connection, "
                "isolate the host, and identify what data was accessible to it.",
            )

        return self._raise(
            ("exfil", src, dst), "Data Exfiltration", src, dst, ts,
            base="High", ratio=win.total / cfg.exfil_bytes,
            protocol="TCP", packets=win.packets, build=build,
        )

    # -- alert lifecycle ----------------------------------------------------

    def _raise(
        self,
        key: Hashable,
        attack_type: str,
        src: str,
        dst: str,
        ts: float,
        *,
        base: str,
        ratio: float,
        protocol: str,
        packets: int,
        build: Builder,
    ) -> Optional[Alert]:
        severity = _bump(base, ratio)
        confidence = _confidence(ratio)

        existing = self._active.get(key)
        if existing and ts - existing[1] < self.cfg.alert_cooldown:
            alert = existing[0]
            alert["packet_count"] = max(alert["packet_count"], packets)
            alert["confidence"] = max(alert["confidence"], confidence)
            if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(alert["severity"]):
                alert["severity"] = severity
            alert["last_seen"] = iso(ts)
            # Keep the evidence text in step with the growing counts.
            if packets > self._last_rebuild.get(key, 0):
                alert["evidence"], alert["analysis"], alert["recommendation"] = build()
                self._last_rebuild[key] = packets
            self._active[key] = (alert, ts)
            return None

        self._seq += 1
        evidence, analysis, recommendation = build()
        alert = {
            "id": f"AEG-{self._seq:04d}",
            "attack_type": attack_type,
            "source_ip": src,
            "destination_ip": dst,
            "severity": severity,
            "confidence": confidence,
            "status": "New",
            "protocol": protocol,
            "packet_count": packets,
            "timestamp": iso(ts),
            "last_seen": iso(ts),
            "evidence": evidence,
            "analysis": analysis,
            "recommendation": recommendation,
        }
        self._active[key] = (alert, ts)
        self._last_rebuild[key] = packets
        return alert

    def reset_alerts(self) -> None:
        """Forget active alerts so continuing activity raises fresh ones."""
        self._active.clear()
        self._last_rebuild.clear()

    def _gc(self, now: float) -> None:
        cfg = self.cfg
        tables = (
            (self._scan, cfg.port_scan_window),
            (self._sweep, cfg.sweep_window),
            (self._flood, cfg.syn_flood_window),
            (self._brute, cfg.brute_window),
            (self._icmp, cfg.icmp_flood_window),
            (self._exfil, cfg.exfil_window),
        )
        for table, horizon in tables:
            for key, win in list(table.items()):
                win.prune(now, horizon)
                if not win.items:
                    del table[key]
        for key, (_, last) in list(self._active.items()):
            if now - last > cfg.alert_cooldown * 2:
                del self._active[key]
                self._last_rebuild.pop(key, None)


# --------------------------------------------------------------------------
# thread-safe wrapper used by the API
# --------------------------------------------------------------------------


class ThreatMonitor:
    """Thread-safe detector + bounded alert store (newest first)."""

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        source: str = "unknown",
        max_alerts: int = 500,
    ) -> None:
        self.source = source
        self._detector = ThreatDetector(config)
        self._alerts: Deque[Alert] = deque(maxlen=max_alerts)
        self._lock = threading.Lock()
        self.started_at = time.time()

    def process(self, pkt: Packet) -> List[Alert]:
        with self._lock:
            new = self._detector.ingest(pkt)
            for alert in new:
                alert["data_source"] = self.source
                self._alerts.appendleft(alert)
            return copy.deepcopy(new)

    def latest(self, limit: int = 100) -> List[Alert]:
        with self._lock:
            return copy.deepcopy(list(self._alerts)[: max(0, limit)])

    def clear(self) -> int:
        with self._lock:
            n = len(self._alerts)
            self._alerts.clear()
            self._detector.reset_alerts()
            return n

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_sev = {s: 0 for s in SEVERITY_ORDER}
            for a in self._alerts:
                by_sev[a["severity"]] += 1
            return {
                "packets_seen": self._detector.packets_seen,
                "alerts_stored": len(self._alerts),
                "alerts_by_severity": by_sev,
                "uptime_seconds": round(time.time() - self.started_at, 1),
            }
