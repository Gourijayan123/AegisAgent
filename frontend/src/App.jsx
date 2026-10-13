
import { useCallback, useEffect, useMemo, useState } from "react";
import "./App.css";

const API_URL = (
  import.meta.env.VITE_API_URL || "http://localhost:8000"
).replace(/\/$/, "");

const DEMO_ALERTS = [
  {
    id: "AEG-001",
    attack_type: "Port Scan",
    source_ip: "192.168.1.10",
    destination_ip: "192.168.1.20",
    severity: "High",
    confidence: 94,
    timestamp: new Date().toISOString(),
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
    timestamp: new Date(Date.now() - 60000).toISOString(),
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
    timestamp: new Date(Date.now() - 180000).toISOString(),
    status: "Resolved",
    protocol: "UDP",
    packet_count: 24,
    evidence: ["Unusual connection timing"],
    analysis:
      "An unusual connection pattern was recorded. The current evidence is insufficient to confirm malicious activity.",
    recommendation: "Continue routine monitoring.",
  },
];

const NAV_ITEMS = [
  "Overview",
  "Threats",
  "Network",
  "AI Analysis",
];

function normalizeAlert(item, index = 0) {
  const rawSeverity = String(
    item.severity || item.risk_level || "Medium"
  ).toLowerCase();

  const severityMap = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };

  const rawConfidence = Number(item.confidence ?? 0);
  const confidence = rawConfidence <= 1
    ? Math.round(rawConfidence * 100)
    : Math.round(rawConfidence);

  return {
    ...item,
    id: String(item.id || item.alert_id || `AEG-${index + 1}`),
    attack_type:
      item.attack_type || item.threat_type || item.type || "Unknown threat",
    source_ip: item.source_ip || item.src_ip || item.source || "Unknown",
    destination_ip:
      item.destination_ip || item.dst_ip || item.destination || "Unknown",
    severity: severityMap[rawSeverity] || "Medium",
    confidence: Math.max(0, Math.min(100, confidence)),
    timestamp: item.timestamp || item.time || new Date().toISOString(),
    status: item.status || "New",
    evidence: Array.isArray(item.evidence)
      ? item.evidence
      : item.evidence
        ? [String(item.evidence)]
        : [],
    analysis: item.analysis || item.ai_analysis || "",
    recommendation: item.recommendation || "",
  };
}

function formatTime(timestamp) {
  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return String(timestamp || "Unknown");
  }

  return date.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function Severity({ value }) {
  const severity = String(value || "Medium").toLowerCase();

  return (
    <span className={`severity severity-${severity}`}>
      <span className="severity-dot" />
      {value || "Medium"}
    </span>
  );
}

function SectionHeading({ eyebrow, title, description, children }) {
  return (
    <div className="section-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
        {description && <p className="section-description">{description}</p>}
      </div>
      {children && <div className="heading-actions">{children}</div>}
    </div>
  );
}

export default function App() {
  const [activePage, setActivePage] = useState("Overview");
  const [alerts, setAlerts] = useState(DEMO_ALERTS);
  const [selectedId, setSelectedId] = useState("AEG-001");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [connection, setConnection] = useState("Demo mode");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notice, setNotice] = useState("");

  const selectedAlert = alerts.find((alert) => alert.id === selectedId)
    || alerts[0]
    || null;

  const refreshAlerts = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_URL}/api/alerts/latest`, {
        headers: { Accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const result = await response.json();

      const items = Array.isArray(result)
        ? result
        : Array.isArray(result.alerts)
          ? result.alerts
          : result.threat_detected !== undefined
            ? [result]
            : result.attack_type || result.threat_type
              ? [result]
              : null;

      if (!items) {
        throw new Error("Unexpected response format from the alerts API.");
      }

      const normalized = items.map(normalizeAlert);

      setAlerts(normalized);
      setConnection("Connected");
      setLastUpdated(new Date());

      if (
        normalized.length &&
        !normalized.some((alert) => alert.id === selectedId)
      ) {
        setSelectedId(normalized[0].id);
      }
    } catch (err) {
      setConnection("Demo mode");
      setError(
        `Could not load live alerts: ${err.message}. Displaying demonstration data.`
      );
    } finally {
      setLoading(false);
    }
  }, [selectedId]);

  useEffect(() => {
    refreshAlerts();
  }, [refreshAlerts]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const searchable = [
        alert.id,
        alert.attack_type,
        alert.source_ip,
        alert.destination_ip,
        alert.severity,
        alert.status,
      ]
        .join(" ")
        .toLowerCase();

      const matchesQuery = searchable.includes(query.toLowerCase());
      const matchesSeverity =
        severityFilter === "All" || alert.severity === severityFilter;
      const matchesStatus =
        statusFilter === "All" || alert.status === statusFilter;

      return matchesQuery && matchesSeverity && matchesStatus;
    });
  }, [alerts, query, severityFilter, statusFilter]);

  const stats = useMemo(() => ({
    total: alerts.length,
    high: alerts.filter((a) =>
      ["High", "Critical"].includes(a.severity)
    ).length,
    investigated: alerts.filter((a) =>
      ["Investigating", "Under review"].includes(a.status)
    ).length,
    critical: alerts.filter((a) => a.severity === "Critical").length,
  }), [alerts]);

  function openAlert(alert) {
    setSelectedId(alert.id);
    setNotice("");
  }

  function updateStatus(alert, status) {
    setAlerts((current) =>
      current.map((item) =>
        item.id === alert.id ? { ...item, status } : item
      )
    );

    setNotice(
      `Status changed to "${status}" in this session. Connect a backend update endpoint to persist it.`
    );
  }

  function exportAlerts() {
    const blob = new Blob([JSON.stringify(alerts, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "aegisagent-alerts.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileMenuOpen ? "sidebar-open" : ""}`}>
        <a className="brand" href="#overview" onClick={() => {
          setActivePage("Overview");
          setMobileMenuOpen(false);
        }}>
          <span className="brand-symbol">A</span>
          <span>
            <strong>AEGISAGENT</strong>
            <small>NETWORK INTELLIGENCE</small>
          </span>
        </a>

        <div className="nav-label">WORKSPACE</div>

        <nav className="navigation">
          {NAV_ITEMS.map((item, index) => (
            <button
              key={item}
              className={`nav-item ${activePage === item ? "nav-active" : ""}`}
              onClick={() => {
                setActivePage(item);
                setMobileMenuOpen(false);
              }}
            >
              <span className="nav-index">0{index + 1}</span>
              <span>{item}</span>
              {item === "Threats" && (
                <span className="nav-count">{alerts.length}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-box">
            <span className={`connection-dot ${connection === "Connected" ? "connected" : ""}`} />
            <div>
              <strong>{connection}</strong>
              <p>
                {connection === "Connected"
                  ? "Live API response"
                  : "Using sample records"}
              </p>
            </div>
          </div>

          <div className="sidebar-footnote">
            AEGISAGENT / PROTOTYPE 0.2
          </div>
        </div>
      </aside>

      {mobileMenuOpen && (
        <button
          className="mobile-overlay"
          onClick={() => setMobileMenuOpen(false)}
          aria-label="Close navigation"
        />
      )}

      <main className="main-area">
        <header className="topbar">
          <button
            className="mobile-menu-button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation"
          >
            MENU
          </button>

          <div className="breadcrumb">
            SECURITY OPERATIONS <span>/</span> {activePage.toUpperCase()}
          </div>

          <div className="topbar-right">
            <span className={`connection-label ${connection === "Connected" ? "live" : ""}`}>
              <span className="connection-dot" />
              {connection}
            </span>
            <span className="user-label">MJ / ADMIN</span>
          </div>
        </header>

        <div className="page-content">
          <section className="hero">
            <div className="hero-copy">
              <div className="eyebrow">
                NETWORK SECURITY / INTELLIGENCE PLATFORM
              </div>

              <h1>
                Security,
                <br />
                without the
                <br />
                <span>blind spots.</span>
              </h1>

              <p className="hero-description">
                Detect suspicious traffic. Understand the evidence.
                Make informed security decisions.
              </p>

              <div className="hero-buttons">
                <button
                  className="button-primary"
                  onClick={() => setActivePage("Threats")}
                >
                  Explore threat activity <span>↗</span>
                </button>

                <button
                  className="button-secondary"
                  onClick={refreshAlerts}
                  disabled={loading}
                >
                  {loading ? "Refreshing..." : "Refresh data"}
                </button>
              </div>

              <div className="hero-caption">
                <span>DETECT</span>
                <span className="caption-divider" />
                <span>INVESTIGATE</span>
                <span className="caption-divider" />
                <span>RESPOND</span>
              </div>
            </div>

            <div className="hero-visual" aria-label="Abstract geometric security illustration">
              <div className="visual-topline">
                <span>AEGIS / 001</span>
                <span>SECURITY INTELLIGENCE</span>
              </div>

              <div className="visual-grid">
                <div className="visual-square square-one" />
                <div className="visual-square square-two" />
                <div className="visual-square square-three" />
                <div className="visual-circle">
                  <div className="circle-inner" />
                </div>
                <div className="visual-bar" />
                <div className="visual-crosshair" />
              </div>

              <div className="visual-bottomline">
                <strong>Observe.</strong>
                <strong>Understand.</strong>
                <strong>Act.</strong>
              </div>
            </div>

            <div className="hero-bottom">
              <span>BUILT FOR NETWORK VISIBILITY</span>
              <span>01 — SECURITY OVERVIEW</span>
            </div>
          </section>

          {error && (
            <div className="notice notice-warning" role="status">
              {error}
            </div>
          )}

          {notice && (
            <div className="notice" role="status">
              {notice}
            </div>
          )}

          {activePage === "Overview" && (
            <OverviewPage
              stats={stats}
              alerts={filteredAlerts}
              selectedAlert={selectedAlert}
              query={query}
              setQuery={setQuery}
              setActivePage={setActivePage}
              openAlert={openAlert}
              loading={loading}
              lastUpdated={lastUpdated}
              exportAlerts={exportAlerts}
            />
          )}

          {activePage === "Threats" && (
            <ThreatsPage
              alerts={filteredAlerts}
              selectedAlert={selectedAlert}
              query={query}
              setQuery={setQuery}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              statusFilter={statusFilter}
              setStatusFilter={setStatusFilter}
              openAlert={openAlert}
              exportAlerts={exportAlerts}
              loading={loading}
              refreshAlerts={refreshAlerts}
            />
          )}

          {activePage === "Network" && (
            <NetworkPage
              alerts={alerts}
              selectedAlert={selectedAlert}
              openAlert={openAlert}
            />
          )}

          {activePage === "AI Analysis" && (
            <AnalysisPage
              alerts={alerts}
              selectedAlert={selectedAlert}
              openAlert={openAlert}
            />
          )}

          <footer className="page-footer">
            <strong>AEGISAGENT</strong>
            <span>Network intelligence for informed response.</span>
            <span>PROTOTYPE / 0.2</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function OverviewPage({
  stats,
  alerts,
  selectedAlert,
  query,
  setQuery,
  setActivePage,
  openAlert,
  loading,
  lastUpdated,
  exportAlerts,
}) {
  return (
    <>
      <SectionHeading
        eyebrow="THE CURRENT PICTURE"
        title="Security overview"
        description="A consolidated view of observed threat activity."
      >
        <button className="button-secondary" onClick={exportAlerts}>
          Export JSON
        </button>
      </SectionHeading>

      <div className="stats-grid">
        <StatCard
          label="Threat events"
          value={stats.total}
          note="Records currently loaded"
          variant="green"
        />
        <StatCard
          label="High / critical"
          value={stats.high}
          note="Requires attention"
          variant="coral"
        />
        <StatCard
          label="Under investigation"
          value={stats.investigated}
          note="Open or under review"
          variant="plain"
        />
      </div>

      <section className="content-section">
        <SectionHeading
          eyebrow="EVENT INTELLIGENCE"
          title="Recent threat activity"
          description="Select any event to inspect its details and supporting evidence."
        >
          <button className="text-button" onClick={() => setActivePage("Threats")}>
            All threats <span>↗</span>
          </button>
        </SectionHeading>

        <div className="toolbar">
          <input
            className="search-input"
            placeholder="Search attack type or IP address"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <span className="record-count">
            {loading ? "Updating..." : `${alerts.length} records`}
          </span>
        </div>

        <ThreatTable alerts={alerts} openAlert={openAlert} />
        <div className="table-footer">
          <span>Data is based on the currently loaded records.</span>
          <span>
            {lastUpdated
              ? `Last API response: ${lastUpdated.toLocaleTimeString()}`
              : "No successful live API response yet"}
          </span>
        </div>
      </section>

      {selectedAlert && (
        <section className="content-section">
          <SectionHeading
            eyebrow="INVESTIGATION SNAPSHOT"
            title="Selected event"
            description="Inspect the current alert without leaving the overview."
          />

          <InvestigationPanel alert={selectedAlert} />
        </section>
      )}
    </>
  );
}

function ThreatsPage({
  alerts,
  selectedAlert,
  query,
  setQuery,
  severityFilter,
  setSeverityFilter,
  statusFilter,
  setStatusFilter,
  openAlert,
  exportAlerts,
  loading,
  refreshAlerts,
}) {
  return (
    <>
      <SectionHeading
        eyebrow="DETECTION & TRIAGE"
        title="Threat intelligence"
        description="Search, filter, and inspect the alerts returned by the detection system."
      >
        <button className="button-secondary" onClick={exportAlerts}>
          Export JSON
        </button>
        <button className="button-primary" onClick={refreshAlerts} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh alerts"}
        </button>
      </SectionHeading>

      <div className="filter-bar">
        <input
          className="search-input"
          placeholder="Search event, source, destination..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />

        <select
          className="filter-select"
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
          aria-label="Filter by severity"
        >
          <option>All</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>

        <select
          className="filter-select"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          aria-label="Filter by status"
        >
          <option>All</option>
          <option>New</option>
          <option>Investigating</option>
          <option>Under review</option>
          <option>Resolved</option>
        </select>
      </div>

      <div className="table-footer">
        <span>{alerts.length} matching events</span>
        <span>Severity is supplied by the detection pipeline.</span>
      </div>

      <ThreatTable alerts={alerts} openAlert={openAlert} />

      {selectedAlert && (
        <section className="content-section">
          <SectionHeading
            eyebrow="SELECTED ALERT"
            title={selectedAlert.attack_type}
          />
          <InvestigationPanel alert={selectedAlert} />
        </section>
      )}
    </>
  );
}

function NetworkPage({ alerts, selectedAlert, openAlert }) {
  const sources = [...new Set(alerts.map((a) => a.source_ip))];
  const destinations = [...new Set(alerts.map((a) => a.destination_ip))];

  return (
    <>
      <SectionHeading
        eyebrow="NETWORK VISIBILITY"
        title="Traffic observations"
        description="Source and destination information from the currently loaded threat events."
      />

      <div className="stats-grid">
        <StatCard label="Unique sources" value={sources.length} note="Observed source addresses" variant="green" />
        <StatCard label="Unique destinations" value={destinations.length} note="Observed destination addresses" variant="plain" />
        <StatCard label="Events loaded" value={alerts.length} note="Current alert dataset" variant="coral" />
      </div>

      <section className="content-section">
        <SectionHeading
          eyebrow="OBSERVED CONNECTIONS"
          title="Traffic event list"
          description="This view is based on detected events, not a live packet stream."
        />
        <ThreatTable alerts={alerts} openAlert={openAlert} />
      </section>

      {selectedAlert && (
        <section className="content-section">
          <SectionHeading eyebrow="CONNECTION DETAIL" title="Selected connection" />
          <InvestigationPanel alert={selectedAlert} />
        </section>
      )}
    </>
  );
}

function AnalysisPage({ alerts, selectedAlert, openAlert }) {
  return (
    <>
      <SectionHeading
        eyebrow="AGENTIC INVESTIGATION"
        title="AI threat analysis"
        description="Review evidence and recommendations associated with detected events."
      />

      <div className="analysis-banner">
        <div className="eyebrow">INVESTIGATION WORKFLOW</div>
        <h3>Evidence first. Recommendations second.</h3>
        <p>
          The investigation panel displays analysis returned with an alert.
          It does not fabricate an AI response when the backend has not
          supplied one.
        </p>
      </div>

      <section className="content-section">
        <SectionHeading eyebrow="AVAILABLE EVENTS" title="Choose an investigation" />
        <ThreatTable alerts={alerts} openAlert={openAlert} />
      </section>

      {selectedAlert && (
        <section className="content-section">
          <SectionHeading
            eyebrow="INVESTIGATION RESULT"
            title={selectedAlert.attack_type}
          />
          <InvestigationPanel alert={selectedAlert} />
        </section>
      )}
    </>
  );
}

function StatCard({ label, value, note, variant }) {
  return (
    <article className={`stat-card stat-${variant}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-note">{note}</div>
    </article>
  );
}

function ThreatTable({ alerts, openAlert }) {
  if (!alerts.length) {
    return (
      <div className="empty-state">
        <h3>No matching events</h3>
        <p>Try changing your search or filters.</p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="threat-table">
        <thead>
          <tr>
            <th>EVENT</th>
            <th>SOURCE IP</th>
            <th>DESTINATION IP</th>
            <th>SEVERITY</th>
            <th>STATUS</th>
            <th>TIME</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>
                <button className="table-event" onClick={() => openAlert(alert)}>
                  <strong>{alert.attack_type}</strong>
                  <small>{alert.id}</small>
                </button>
              </td>
              <td className="mono">{alert.source_ip}</td>
              <td className="mono">{alert.destination_ip}</td>
              <td><Severity value={alert.severity} /></td>
              <td><span className="status-label">{alert.status}</span></td>
              <td className="time-cell">{formatTime(alert.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function InvestigationPanel({ alert }) {
  return (
    <div className="investigation-layout">
      <article className="detail-card">
        <div className="detail-overline">DETECTED EVENT</div>
        <div className="detail-title-row">
          <h3>{alert.attack_type}</h3>
          <Severity value={alert.severity} />
        </div>

        <div className="detail-grid">
          <DetailField label="SOURCE IP" value={alert.source_ip} />
          <DetailField label="DESTINATION IP" value={alert.destination_ip} />
          <DetailField label="CONFIDENCE" value={`${alert.confidence}%`} />
          <DetailField label="PROTOCOL" value={alert.protocol || "Not provided"} />
          <DetailField label="PACKETS" value={alert.packet_count ?? "Not provided"} />
          <DetailField label="DETECTED AT" value={formatTime(alert.timestamp)} />
        </div>

        <div className="detail-overline detail-subheading">CURRENT STATUS</div>
        <p className="detail-paragraph">{alert.status}</p>
      </article>

      <article className="detail-card">
        <div className="detail-overline">EVIDENCE & INDICATORS</div>

        {alert.evidence?.length ? (
          <ol className="evidence-list">
            {alert.evidence.map((evidence, index) => (
              <li key={`${index}-${String(evidence)}`}>
                <span className="evidence-index">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span>{typeof evidence === "string" ? evidence : JSON.stringify(evidence)}</span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="detail-paragraph">
            No evidence was supplied by the detection backend.
          </p>
        )}

        <div className="detail-overline detail-subheading">AI ANALYSIS</div>
        <p className="detail-paragraph">
          {alert.analysis || "No AI analysis has been returned for this event."}
        </p>

        <div className="recommendation-box">
          <div className="detail-overline">RECOMMENDED NEXT STEP</div>
          <p>
            {alert.recommendation ||
              "No recommendation has been returned. Investigate the evidence before taking action."}
          </p>
        </div>
      </article>
    </div>
  );
}

function DetailField({ label, value }) {
  return (
    <div className="detail-field">
      <span>{label}</span>
      <strong>{String(value ?? "Not provided")}</strong>
    </div>
  );
}
