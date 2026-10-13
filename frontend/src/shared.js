import { createContext } from "react";

// Actions shared across pages (status changes, blocklist, notes, toasts).
export const ActionsContext = createContext(null);

export function downloadFile(filename, text, type = "text/plain") {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function alertsToCsv(alerts) {
  const columns = [
    "id",
    "attack_type",
    "source_ip",
    "destination_ip",
    "severity",
    "confidence",
    "status",
    "protocol",
    "packet_count",
    "timestamp",
  ];
  const escape = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  const rows = alerts.map((alert) =>
    columns.map((column) => escape(alert[column])).join(",")
  );
  return [columns.join(","), ...rows].join("\n");
}

export function buildReport(alert, result) {
  const lines = [
    `# AegisAgent investigation report`,
    ``,
    `**Event:** ${alert.attack_type} (${alert.id})`,
    `**Severity:** ${alert.severity}  |  **Confidence:** ${alert.confidence}%`,
    `**Source:** ${alert.source_ip}  ->  **Destination:** ${alert.destination_ip}`,
    `**Status:** ${alert.status}`,
    ``,
    `## Evidence`,
    ...(alert.evidence?.length ? alert.evidence.map((e) => `- ${e}`) : ["- None supplied"]),
    ``,
    `## Analysis`,
    result?.summary || alert.analysis || "No analysis available.",
    ``,
    `## Recommended steps`,
    ...((result?.steps || [alert.recommendation || "Investigate before acting."]).map(
      (step, i) => `${i + 1}. ${step}`
    )),
  ];

  if (result) {
    lines.push(``, `## Risk score`, `${result.riskScore}/100 (simulated demo analysis)`);
  }
  if (alert.notes?.length) {
    lines.push(``, `## Analyst notes`, ...alert.notes.map((n) => `- [${n.time}] ${n.text}`));
  }
  return lines.join("\n");
}