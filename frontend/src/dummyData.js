// All dummy / demo data for the dashboard lives here.
// Replace these with real API calls when the backend is ready.

const NOW = Date.now();
const minutesAgo = (m) => new Date(NOW - m * 60000).toISOString();

export const DEMO_ALERTS = [
  {
    id: "AEG-001",
    attack_type: "Port Scan",
    source_ip: "192.168.1.10",
    destination_ip: "192.168.1.20",
    severity: "High",
    confidence: 94,
    timestamp: minutesAgo(0),
    status: "Investigating",
    protocol: "TCP",
    packet_count: 150,
    evidence: [
      "Multiple destination ports contacted",
      "Repeated connection attempts within a short interval",
      "Unusual connection pattern detected",
    ],
    analysis:
      "The traffic pattern is consistent with possible reconnaissance activity. Verify the destination ports, timestamps, and source activity before taking action.",
    recommendation: "Investigate the source and monitor subsequent traffic.",
  },
  {
    id: "AEG-002",
    attack_type: "Suspicious Traffic",
    source_ip: "192.168.1.15",
    destination_ip: "192.168.1.30",
    severity: "Medium",
    confidence: 76,
    timestamp: minutesAgo(1),
    status: "Under review",
    protocol: "TCP",
    packet_count: 82,
    evidence: [
      "Unusual traffic frequency",
      "Additional packet inspection required",
    ],
    analysis:
      "The observed traffic differs from the expected pattern. More context is required to determine whether the activity is malicious.",
    recommendation: "Review the traffic logs and monitor the source.",
  },
  {
    id: "AEG-003",
    attack_type: "Connection Anomaly",
    source_ip: "192.168.1.22",
    destination_ip: "192.168.1.5",
    severity: "Low",
    confidence: 61,
    timestamp: minutesAgo(3),
    status: "Resolved",
    protocol: "UDP",
    packet_count: 24,
    evidence: ["Unusual connection timing"],
    analysis:
      "An unusual connection pattern was recorded. The current evidence is insufficient to confirm malicious activity.",
    recommendation: "Continue routine monitoring.",
  },
  {
    id: "AEG-004",
    attack_type: "SYN Flood",
    source_ip: "203.0.113.45",
    destination_ip: "192.168.1.5",
    severity: "Critical",
    confidence: 97,
    timestamp: minutesAgo(6),
    status: "New",
    protocol: "TCP",
    packet_count: 48210,
    evidence: [
      "Spike of half-open TCP connections",
      "Thousands of SYN packets from a single external address",
      "Server connection table nearing capacity",
    ],
    analysis:
      "Volume and packet flags are consistent with a SYN flood aimed at exhausting connection resources on the destination host.",
    recommendation: "Rate-limit or block the source and enable SYN cookies.",
  },
  {
    id: "AEG-005",
    attack_type: "SSH Brute Force",
    source_ip: "198.51.100.23",
    destination_ip: "192.168.1.12",
    severity: "High",
    confidence: 91,
    timestamp: minutesAgo(11),
    status: "New",
    protocol: "TCP",
    packet_count: 1340,
    evidence: [
      "212 failed SSH logins in 4 minutes",
      "Dictionary-style username rotation",
      "Single source targeting one host",
    ],
    analysis:
      "Repeated failed authentication attempts with rotating usernames strongly indicate an automated credential-guessing attack.",
    recommendation: "Block the source, enforce key-based auth, and review SSH logs.",
  },
  {
    id: "AEG-006",
    attack_type: "DNS Tunneling",
    source_ip: "192.168.1.41",
    destination_ip: "8.8.4.4",
    severity: "High",
    confidence: 83,
    timestamp: minutesAgo(18),
    status: "Investigating",
    protocol: "UDP",
    packet_count: 3920,
    evidence: [
      "Unusually long DNS query names",
      "High volume of TXT record requests",
      "Encoded-looking subdomain strings",
    ],
    analysis:
      "The DNS behaviour resembles data being encoded into queries, a common covert channel technique. Confirm with a packet capture.",
    recommendation: "Inspect DNS logs for the host and isolate it if exfiltration is confirmed.",
  },
  {
    id: "AEG-007",
    attack_type: "Data Exfiltration",
    source_ip: "192.168.1.67",
    destination_ip: "203.0.113.200",
    severity: "Critical",
    confidence: 88,
    timestamp: minutesAgo(26),
    status: "Under review",
    protocol: "TCP",
    packet_count: 15840,
    evidence: [
      "Large outbound transfer outside business hours",
      "Destination not seen before on this network",
      "Sustained upload with little inbound traffic",
    ],
    analysis:
      "An unusually large, one-directional upload to a new external host suggests possible data theft. Validate with the host owner.",
    recommendation: "Isolate the host pending review and preserve logs.",
  },
  {
    id: "AEG-008",
    attack_type: "Malware Beaconing",
    source_ip: "192.168.1.54",
    destination_ip: "198.51.100.77",
    severity: "Medium",
    confidence: 72,
    timestamp: minutesAgo(35),
    status: "New",
    protocol: "TCP",
    packet_count: 640,
    evidence: [
      "Connections at near-constant 60 second intervals",
      "Small, uniform payload sizes",
    ],
    analysis:
      "Regular, low-volume check-ins resemble command-and-control beaconing, but legitimate update agents can look similar.",
    recommendation: "Identify the process behind the connection and scan the host.",
  },
  {
    id: "AEG-009",
    attack_type: "ARP Spoofing",
    source_ip: "192.168.1.88",
    destination_ip: "192.168.1.1",
    severity: "Medium",
    confidence: 68,
    timestamp: minutesAgo(52),
    status: "Resolved",
    protocol: "ARP",
    packet_count: 310,
    evidence: [
      "Gateway MAC address changed twice in 10 minutes",
      "Gratuitous ARP replies from a non-gateway host",
    ],
    analysis:
      "Conflicting ARP replies for the gateway address can indicate a man-in-the-middle attempt or a misconfigured device.",
    recommendation: "Enable dynamic ARP inspection and verify the device at the source address.",
  },
  {
    id: "AEG-010",
    attack_type: "SQL Injection Attempt",
    source_ip: "203.0.113.9",
    destination_ip: "192.168.1.30",
    severity: "Low",
    confidence: 58,
    timestamp: minutesAgo(75),
    status: "Resolved",
    protocol: "HTTP",
    packet_count: 96,
    evidence: ["Query strings containing SQL keywords", "Requests blocked by the WAF"],
    analysis:
      "A handful of requests carried common injection payloads. The WAF blocked them and no successful responses were observed.",
    recommendation: "Keep WAF rules updated and monitor for repeat attempts.",
  },
];

export const INITIAL_NOTIFICATIONS = [
  { id: "n1", alertId: "AEG-004", text: "Critical: SYN flood detected against 192.168.1.5", time: "6 min ago", read: false },
  { id: "n2", alertId: "AEG-005", text: "SSH brute force from 198.51.100.23", time: "11 min ago", read: false },
  { id: "n3", alertId: "AEG-007", text: "Large outbound transfer from 192.168.1.67", time: "26 min ago", read: false },
  { id: "n4", alertId: "AEG-006", text: "DNS tunneling pattern flagged", time: "18 min ago", read: true },
  { id: "n5", alertId: "AEG-009", text: "ARP spoofing alert marked resolved", time: "52 min ago", read: true },
];

// ---------- Traffic ----------

function seeded(seed) {
  let s = seed;
  return () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

export const TRAFFIC_RANGES = ["1H", "24H", "7D"];

export function makeTrafficSeries(range) {
  const config = {
    "1H": { count: 30, seed: 11, base: 520, wave: 140 },
    "24H": { count: 24, seed: 29, base: 640, wave: 260 },
    "7D": { count: 28, seed: 47, base: 580, wave: 200 },
  }[range];

  const random = seeded(config.seed);
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  const values = Array.from({ length: config.count }, (_, i) => {
    const wave = Math.sin((i / config.count) * Math.PI * 3) * config.wave;
    const noise = (random() - 0.5) * config.wave * 0.9;
    const spike = random() > 0.92 ? config.wave * 1.1 : 0;
    return Math.max(80, config.base + wave + noise + spike);
  });

  const labels = values.map((_, i) => {
    if (range === "1H") return `${config.count - 1 - i} min ago`;
    if (range === "24H") return `${String(i).padStart(2, "0")}:00`;
    return `${days[Math.floor(i / 4)]} ${String((i % 4) * 6).padStart(2, "0")}:00`;
  });

  return { values, labels };
}

export function makeLiveSeed(count = 40) {
  const random = seeded(73);
  return Array.from({ length: count }, (_, i) =>
    Math.round(420 + Math.sin(i / 4) * 90 + random() * 80)
  );
}

export const PROTOCOL_MIX = [
  { name: "TCP", value: 52, color: "#0ea5e9" },
  { name: "UDP", value: 21, color: "#43f58a" },
  { name: "HTTPS", value: 14, color: "#176d39" },
  { name: "DNS", value: 7, color: "#dfb94d" },
  { name: "ICMP", value: 4, color: "#f05a43" },
  { name: "Other", value: 2, color: "#a4a797" },
];

export const TOP_TALKERS = [
  { ip: "192.168.1.67", role: "Workstation", connections: 612, megabytes: 1842.6 },
  { ip: "203.0.113.45", role: "External", connections: 48210, megabytes: 904.2 },
  { ip: "192.168.1.41", role: "Workstation", connections: 3920, megabytes: 311.8 },
  { ip: "192.168.1.10", role: "Server", connections: 482, megabytes: 276.4 },
  { ip: "198.51.100.23", role: "External", connections: 1340, megabytes: 58.9 },
  { ip: "192.168.1.15", role: "Workstation", connections: 82, megabytes: 24.1 },
];

export const SCAN_DEVICES = [
  { name: "gateway-01", ip: "192.168.1.1", type: "Router", status: "Online", ports: 4 },
  { name: "web-server", ip: "192.168.1.30", type: "Server", status: "Online", ports: 6 },
  { name: "db-server", ip: "192.168.1.5", type: "Server", status: "Online", ports: 3 },
  { name: "ws-finance-02", ip: "192.168.1.67", type: "Workstation", status: "Online", ports: 2 },
  { name: "printer-3f", ip: "192.168.1.88", type: "Printer", status: "Idle", ports: 1 },
  { name: "unknown-device", ip: "192.168.1.101", type: "Unknown", status: "Unrecognised", ports: 5 },
];

// ---------- AI (simulated) ----------

const ANALYSIS_TEMPLATES = {
  "Port Scan": {
    summary: "A single host is probing many ports, which is typical of reconnaissance before an attack.",
    steps: ["Confirm the scan with firewall logs", "Check whether the source is an approved scanner", "Block or rate-limit the source if unapproved"],
  },
  "SYN Flood": {
    summary: "Half-open connection volume is overwhelming the target, matching a denial-of-service attempt.",
    steps: ["Enable SYN cookies on the target", "Rate-limit or block the offending source", "Notify the upstream provider if traffic persists"],
  },
  "SSH Brute Force": {
    summary: "Many rapid failed logins with rotating usernames indicate automated credential guessing.",
    steps: ["Block the source address", "Disable password auth in favour of keys", "Review successful logins from the same period"],
  },
  "DNS Tunneling": {
    summary: "Encoded-looking DNS queries suggest data may be leaving the network through a covert channel.",
    steps: ["Capture DNS traffic from the host", "Inspect query names for encoded data", "Isolate the host if exfiltration is confirmed"],
  },
  "Data Exfiltration": {
    summary: "A large one-way upload to an unfamiliar external host may mean sensitive data is being removed.",
    steps: ["Contact the host owner to verify the transfer", "Isolate the host pending review", "Preserve logs for forensic analysis"],
  },
};

const GENERIC_TEMPLATE = {
  summary: "The traffic deviates from the normal baseline, but the evidence alone is not conclusive.",
  steps: ["Collect more context from logs", "Monitor the source for repeat activity", "Escalate if the behaviour continues"],
};

export function generateAnalysis(alert) {
  const template = ANALYSIS_TEMPLATES[alert.attack_type] || GENERIC_TEMPLATE;
  const severityWeight = { Critical: 40, High: 30, Medium: 18, Low: 8 }[alert.severity] ?? 18;
  const riskScore = Math.min(99, Math.round(severityWeight + alert.confidence * 0.55));

  return {
    summary: template.summary,
    steps: template.steps,
    riskScore,
    generatedAt: new Date().toISOString(),
  };
}

export const SUGGESTED_QUESTIONS = [
  "Summarize this alert",
  "How risky is this?",
  "What should I do next?",
  "Could this be a false positive?",
];

export function aiReply(question, alert) {
  const q = question.toLowerCase();
  const name = alert.attack_type;

  if (q.includes("summar")) {
    return `${name} from ${alert.source_ip} to ${alert.destination_ip} (${alert.severity} severity, ${alert.confidence}% confidence). ${alert.analysis || "No further analysis has been supplied."}`;
  }
  if (q.includes("risk") || q.includes("severe") || q.includes("danger")) {
    return `I rate this ${alert.severity.toLowerCase()} risk. Confidence is ${alert.confidence}%, and the strongest indicator is: "${alert.evidence?.[0] || "no evidence listed"}".`;
  }
  if (q.includes("false") || q.includes("legit") || q.includes("benign")) {
    return alert.confidence >= 85
      ? `A false positive is unlikely at ${alert.confidence}% confidence, but check whether ${alert.source_ip} belongs to an approved tool or scanner.`
      : `A false positive is plausible at ${alert.confidence}% confidence. Compare against normal behaviour for ${alert.source_ip} before acting.`;
  }
  if (q.includes("next") || q.includes("do") || q.includes("respond") || q.includes("fix") || q.includes("block")) {
    return alert.recommendation || "Review the evidence, then monitor the source before taking action.";
  }
  if (q.includes("evidence") || q.includes("why")) {
    return `Flagged because: ${(alert.evidence || []).join("; ") || "no evidence was supplied"}.`;
  }
  return "I can summarize this alert, rate its risk, suggest next steps, or assess false-positive likelihood. Try one of those.";
}