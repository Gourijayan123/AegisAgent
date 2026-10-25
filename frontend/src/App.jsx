import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import {
  DEMO_ALERTS,
  INITIAL_NOTIFICATIONS,
  generateAnalysis,
} from "./dummyData.js";
import { ActionsContext, alertsToCsv, buildReport, downloadFile } from "./shared.js";
import {
  AiAssistant,
  AlertActions,
  AnalysisRunner,
  BlocklistPanel,
  DeviceScan,
  LiveTrafficPanel,
  NotificationMenu,
  ProtocolMix,
  SeverityBreakdown,
  SignedOutScreen,
  TopTalkers,
  TrafficPanel,
  UserMenu,
} from "./features.jsx";

const API_URL = (
  import.meta.env.VITE_API_URL || "http://localhost:8000"
).replace(/\/$/, "");

// How often the dashboard polls the backend for new detections.
const REFRESH_MS = 5000;
const REQUEST_TIMEOUT_MS = 8000;

const OPEN_STATUSES = ["Investigating", "Under review", "Escalated"];

const NAV_ITEMS = [
  "Overview",
  "Threats",
  "Network",
  "AI Analysis",
];

function pageFromHash() {
  const slug = window.location.hash.replace("#", "").toLowerCase().replace(/-/g, " ");
  return NAV_ITEMS.find((item) => item.toLowerCase() === slug) || "Overview";
}

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

const MOCK_TRAFFIC = [
  22, 30, 26, 38, 34, 46, 40, 52, 44, 58, 50, 66, 48, 54, 72, 60, 64, 80, 62, 70,
];

function HeroDashboardMock({ alerts, stats }) {
  const width = 300;
  const height = 90;
  const max = Math.max(...MOCK_TRAFFIC);
  const points = MOCK_TRAFFIC.map((value, i) => [
    (i / (MOCK_TRAFFIC.length - 1)) * (width - 8),
    height - (value / max) * (height - 10) - 4,
  ]);
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const [lastX, lastY] = points[points.length - 1];
  const recent = alerts.slice(0, 3);

  return (
    <div className="mock" aria-hidden="true">
      <div className="mock-window">
        <div className="mock-chrome">
          <span /><span /><span />
          <em>aegis / overview</em>
          <b className="mock-live"><i /> LIVE</b>
        </div>

        <div className="mock-kpis">
          <div>
            <small>ALERTS</small>
            <strong>{stats.total}</strong>
          </div>
          <div>
            <small>HIGH RISK</small>
            <strong className="mock-hot">{stats.high}</strong>
          </div>
          <div>
            <small>IN REVIEW</small>
            <strong>{stats.investigated}</strong>
          </div>
        </div>

        <div className="mock-chart">
          <div className="mock-chart-title">
            <span>TRAFFIC / PACKETS PER SEC</span>
            <span>24H</span>
          </div>
          <div className="mock-plot">
          <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
            <defs>
              <linearGradient id="mockFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#43f58a" stopOpacity="0.55" />
                <stop offset="100%" stopColor="#43f58a" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[22, 45, 68].map((y) => (
              <line key={y} x1="0" x2={width} y1={y} y2={y} className="mock-gridline" />
            ))}
            <polygon points={`0,${height} ${line} ${lastX.toFixed(1)},${height}`} fill="url(#mockFill)" />
            <polyline points={line} className="mock-line" pathLength="1" />
          </svg>
            <span
              className="mock-dot"
              style={{ left: `${(lastX / width) * 100}%`, top: `${(lastY / height) * 100}%` }}
            />
          </div>
        </div>

        <div className="mock-alerts">
          {recent.map((alert) => (
            <div className="mock-alert" key={alert.id}>
              <span className={`mock-sev mock-sev-${String(alert.severity).toLowerCase()}`} />
              <span className="mock-alert-name">{alert.attack_type}</span>
              <span className="mock-alert-ip">{alert.source_ip}</span>
              <span className="mock-alert-conf">{alert.confidence}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
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

const SPLASH_STEPS = [
  "Initializing sensors",
  "Loading traffic data",
  "Analyzing patterns",
  "Preparing dashboard",
];

function SplashScreen({ ready, onDone }) {
  const [minDone, setMinDone] = useState(false);
  const [maxDone, setMaxDone] = useState(false);
  const [step, setStep] = useState(0);

  useEffect(() => {
    const minTimer = setTimeout(() => setMinDone(true), 2200);
    const maxTimer = setTimeout(() => setMaxDone(true), 6000);
    const stepTimer = setInterval(
      () => setStep((value) => Math.min(value + 1, SPLASH_STEPS.length - 1)),
      650
    );

    return () => {
      clearTimeout(minTimer);
      clearTimeout(maxTimer);
      clearInterval(stepTimer);
    };
  }, []);

  const leaving = maxDone || (ready && minDone);

  useEffect(() => {
    if (!leaving) return undefined;

    const doneTimer = setTimeout(onDone, 650);
    return () => clearTimeout(doneTimer);
  }, [leaving, onDone]);

  return (
    <div
      className={`splash ${leaving ? "splash-leaving" : ""}`}
      role="status"
      aria-live="polite"
      aria-label="Loading AegisAgent"
    >
      <div className="splash-meta splash-meta-top">
        <span>AEGISAGENT / PROTOTYPE 0.2</span>
        <span>SECURE CONNECTION</span>
      </div>

      <div className="splash-center">
        <div className="splash-radar">
          <span className="radar-ring radar-ring-1" />
          <span className="radar-ring radar-ring-2" />
          <span className="radar-ring radar-ring-3" />
          <div className="splash-logo">A</div>
        </div>

        <h1 className="splash-title">AEGISAGENT</h1>
        <p className="splash-tagline">NETWORK INTELLIGENCE</p>

        <div className="splash-progress">
          <div className="splash-bar">
            <div className="splash-bar-fill" />
          </div>
          <div className="splash-status">
            <span key={step}>{SPLASH_STEPS[step]}...</span>
            <span>{String(Math.min((step + 1) * 25, 100)).padStart(3, "0")}%</span>
          </div>
        </div>
      </div>

      <div className="splash-meta splash-meta-bottom">
        <span>OBSERVE</span>
        <span>UNDERSTAND</span>
        <span>ACT</span>
      </div>
    </div>
  );
}

export default function App() {
  const [activePage, setActivePageState] = useState(pageFromHash);
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
  const [notifications, setNotifications] = useState(INITIAL_NOTIFICATIONS);
  const [blocked, setBlocked] = useState(["198.51.100.23"]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [dataSource, setDataSource] = useState("");
  const selectedIdRef = useRef("AEG-001");
  const hasLiveDataRef = useRef(false);
  const knownIdsRef = useRef(new Set());
  const [compact, setCompact] = useState(false);
  const [signedOut, setSignedOut] = useState(false);
  const [initialLoadDone, setInitialLoadDone] = useState(false);
  const [showSplash, setShowSplash] = useState(true);
  const hideSplash = useCallback(() => setShowSplash(false), []);

  useEffect(() => {
    selectedIdRef.current = selectedId;
  }, [selectedId]);

  const selectedAlert = alerts.find((alert) => alert.id === selectedId)
    || alerts[0]
    || null;

  const refreshAlerts = useCallback(async () => {
    setLoading(true);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(`${API_URL}/api/alerts/latest`, {
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const result = await response.json();

      const items = Array.isArray(result)
        ? result
        : result && Array.isArray(result.alerts)
          ? result.alerts
          : null;

      if (!items) {
        throw new Error("Unexpected response format from the alerts API.");
      }

      const fresh = items.map(normalizeAlert);

      // Announce newly detected high-severity threats (not on the first load).
      if (hasLiveDataRef.current) {
        const arrivals = fresh.filter(
          (alert) =>
            !knownIdsRef.current.has(alert.id) &&
            (alert.severity === "Critical" || alert.severity === "High")
        );
        if (arrivals.length) {
          setNotifications((current) => [
            ...arrivals.map((alert) => ({
              id: `live-${alert.id}`,
              alertId: alert.id,
              text: `${alert.severity}: ${alert.attack_type} from ${alert.source_ip}`,
              time: "just now",
              read: false,
            })),
            ...current,
          ].slice(0, 30));
        }
      }
      if (!hasLiveDataRef.current) {
        // First real response: drop notifications that referred to demo alerts.
        setNotifications([]);
      }
      knownIdsRef.current = new Set(fresh.map((alert) => alert.id));
      hasLiveDataRef.current = true;

      // Keep analyst changes (status, notes) made in this session across polls.
      setAlerts((current) => {
        const local = new Map(current.map((alert) => [alert.id, alert]));
        return fresh.map((alert) => {
          const mine = local.get(alert.id);
          return mine
            ? { ...alert, status: mine.status, notes: mine.notes }
            : alert;
        });
      });

      setDataSource(result?.mode || "");
      setConnection("Connected");
      setError("");
      setLastUpdated(new Date());

      if (fresh.length && !fresh.some((alert) => alert.id === selectedIdRef.current)) {
        setSelectedId(fresh[0].id);
      }
    } catch (err) {
      const reason = err.name === "AbortError" ? "request timed out" : err.message;
      if (hasLiveDataRef.current) {
        // Never relabel real detections as demo data; say the feed is stale.
        setConnection("Disconnected");
        setError(`Connection to the alerts API lost (${reason}). Showing the last alerts received.`);
      } else {
        setConnection("Demo mode");
        setError(
          `Could not load live alerts: ${reason}. Displaying demonstration data. ` +
            `Start the backend (see README) to see real detections.`
        );
      }
    } finally {
      clearTimeout(timeout);
      setLoading(false);
      setInitialLoadDone(true);
    }
  }, []);

  useEffect(() => {
    refreshAlerts();
  }, [refreshAlerts]);

  const setActivePage = useCallback((page) => {
    setActivePageState(page);
    const slug = page.toLowerCase().replace(/ /g, "-");
    if (window.location.hash !== `#${slug}`) {
      window.history.pushState(null, "", `#${slug}`);
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  useEffect(() => {
    const onNavigate = () => setActivePageState(pageFromHash());
    window.addEventListener("hashchange", onNavigate);
    window.addEventListener("popstate", onNavigate);
    return () => {
      window.removeEventListener("hashchange", onNavigate);
      window.removeEventListener("popstate", onNavigate);
    };
  }, []);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const timer = setInterval(refreshAlerts, REFRESH_MS);
    return () => clearInterval(timer);
  }, [autoRefresh, refreshAlerts]);

  useEffect(() => {
    if (!notice) return undefined;
    const timer = setTimeout(() => setNotice(""), 5000);
    return () => clearTimeout(timer);
  }, [notice]);

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
        severityFilter === "All" ||
        (severityFilter === "High + Critical"
          ? ["High", "Critical"].includes(alert.severity)
          : alert.severity === severityFilter);
      const matchesStatus =
        statusFilter === "All" ||
        (statusFilter === "Open cases"
          ? OPEN_STATUSES.includes(alert.status)
          : alert.status === statusFilter);

      return matchesQuery && matchesSeverity && matchesStatus;
    });
  }, [alerts, query, severityFilter, statusFilter]);

  const stats = useMemo(() => ({
    total: alerts.length,
    high: alerts.filter((a) =>
      ["High", "Critical"].includes(a.severity)
    ).length,
    investigated: alerts.filter((a) => OPEN_STATUSES.includes(a.status)).length,
    critical: alerts.filter((a) => a.severity === "Critical").length,
  }), [alerts]);

  function openAlert(alert) {
    setSelectedId(alert.id);
    setNotice("");
    requestAnimationFrame(() => {
      document
        .getElementById("investigation")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function openAlertById(id) {
    const match = alerts.find((alert) => alert.id === id);
    if (match) {
      setSelectedId(match.id);
      setQuery("");
      setSeverityFilter("All");
      setStatusFilter("All");
      setActivePage("Threats");
    } else {
      setNotice(`Alert ${id} is no longer in the loaded data.`);
    }
  }

  function goToThreats({ severity = "All", status = "All" } = {}) {
    setQuery("");
    setSeverityFilter(severity);
    setStatusFilter(status);
    setActivePage("Threats");
  }

  function clearFilters() {
    setQuery("");
    setSeverityFilter("All");
    setStatusFilter("All");
  }

  function addNote(alert, text) {
    const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setAlerts((current) =>
      current.map((item) =>
        item.id === alert.id
          ? { ...item, notes: [...(item.notes || []), { text, time }] }
          : item
      )
    );
    setNotice("Note added to this alert (session only).");
  }

  function blockIp(ip) {
    setBlocked((current) => (current.includes(ip) ? current : [...current, ip]));
    setNotice(`${ip} added to the blocklist (simulation only).`);
  }

  function unblockIp(ip) {
    setBlocked((current) => current.filter((item) => item !== ip));
    setNotice(`${ip} removed from the blocklist.`);
  }

  async function copyText(text, message) {
    try {
      await navigator.clipboard.writeText(text);
      setNotice(message);
    } catch {
      setNotice(`Could not access the clipboard. Value: ${text}`);
    }
  }

  function exportCsv() {
    downloadFile("aegisagent-alerts.csv", alertsToCsv(alerts), "text/csv");
    setNotice(`Exported ${alerts.length} alerts as CSV.`);
  }

  const actions = {
    blocked,
    blockIp,
    unblockIp,
    clearBlocked: () => setBlocked([]),
    updateStatus,
    addNote,
    copyText,
    notify: setNotice,
  };

  function updateStatus(alert, status) {
    setAlerts((current) =>
      current.map((item) =>
        item.id === alert.id ? { ...item, status } : item
      )
    );

    setNotice(
      `${alert.id} status changed to "${status}" in this session. Connect a backend update endpoint to persist it.`
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

  if (signedOut) {
    return <SignedOutScreen onSignIn={() => setSignedOut(false)} />;
  }

  return (
    <ActionsContext.Provider value={actions}>
    <div className={`app-shell ${compact ? "compact" : ""}`}>
      {showSplash && (
        <SplashScreen ready={initialLoadDone} onDone={hideSplash} />
      )}
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
          <div
            className="connection-box connection-box-action"
            role="button"
            tabIndex={0}
            title="Retry connection to the alerts API"
            onClick={refreshAlerts}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                refreshAlerts();
              }
            }}
          >
            <span className={`connection-dot ${connection === "Connected" ? "connected" : ""}`} />
            <div>
              <strong>{connection}</strong>
              <p>
                {connection === "Connected"
                  ? dataSource === "simulated"
                    ? "Simulated traffic (demo backend)"
                    : dataSource === "replay"
                      ? "Replayed capture"
                      : "Live detections"
                  : connection === "Disconnected"
                    ? "Showing last alerts received"
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
            <NotificationMenu
              notifications={notifications}
              setNotifications={setNotifications}
              onOpenAlert={openAlertById}
            />
            <UserMenu
              autoRefresh={autoRefresh}
              setAutoRefresh={(value) => {
                setAutoRefresh(value);
                setNotice(value ? `Auto-refresh enabled (every ${REFRESH_MS / 1000} seconds).` : "Auto-refresh disabled.");
              }}
              compact={compact}
              setCompact={setCompact}
              onSignOut={() => setSignedOut(true)}
            />
          </div>
        </header>

        <div className="page-content">
          {activePage === "Overview" && (
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

            <div className="hero-visual" aria-label="Dashboard preview">
              <div className="visual-topline">
                <span>AEGIS / 001</span>
                <span>SECURITY INTELLIGENCE</span>
              </div>
              <HeroDashboardMock alerts={alerts} stats={stats} />

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
          )}

          {error && (
            <div className="notice notice-warning" role="status">
              {error}
            </div>
          )}

          {notice && (
            <div className="toast" role="status" key={notice}>
              <span>{notice}</span>
              <button aria-label="Dismiss message" onClick={() => setNotice("")}>×</button>
            </div>
          )}

          {activePage === "Overview" && (
            <OverviewPage
              stats={stats}
              allAlerts={alerts}
              goToThreats={goToThreats}
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
              exportCsv={exportCsv}
              clearFilters={clearFilters}
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
    </ActionsContext.Provider>
  );
}

function OverviewPage({
  stats,
  allAlerts,
  goToThreats,
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
          onClick={() => goToThreats()}
        />
        <StatCard
          label="High / critical"
          value={stats.high}
          note="Requires attention"
          variant="coral"
          onClick={() => goToThreats({ severity: "High + Critical" })}
        />
        <StatCard
          label="Under investigation"
          value={stats.investigated}
          note="Open or under review"
          variant="plain"
          onClick={() => goToThreats({ status: "Open cases" })}
        />
      </div>

      <div className="overview-split">
        <TrafficPanel />
        <section className="panel">
          <div className="panel-head">
            <span className="panel-title">SEVERITY MIX</span>
          </div>
          <SeverityBreakdown
            alerts={allAlerts}
            onSelect={(severity) => goToThreats({ severity })}
          />
          <p className="panel-empty">Select a level to open those alerts.</p>
        </section>
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

        <ThreatTable alerts={alerts} openAlert={openAlert} selectedId={selectedAlert?.id} />
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
  exportCsv,
  clearFilters,
  loading,
  refreshAlerts,
}) {
  const filtersActive =
    query !== "" || severityFilter !== "All" || statusFilter !== "All";

  return (
    <>
      <SectionHeading
        eyebrow="DETECTION & TRIAGE"
        title="Threat intelligence"
        description="Search, filter, and inspect the alerts returned by the detection system."
      >
        <button className="button-secondary" onClick={exportCsv}>
          Export CSV
        </button>
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
          <option>High + Critical</option>
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
          <option>Open cases</option>
          <option>New</option>
          <option>Investigating</option>
          <option>Under review</option>
          <option>Escalated</option>
          <option>Resolved</option>
        </select>
      </div>

      <div className="table-footer">
        <span>
          {alerts.length} matching events
          {filtersActive && (
            <button className="text-button inline-button" onClick={clearFilters}>
              Clear filters
            </button>
          )}
        </span>
        <span>Severity is supplied by the detection pipeline.</span>
      </div>

      <ThreatTable alerts={alerts} openAlert={openAlert} selectedId={selectedAlert?.id} />

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

      <div className="content-section">
        <LiveTrafficPanel />
      </div>

      <div className="two-col">
        <ProtocolMix />
        <BlocklistPanel />
      </div>

      <TopTalkers />

      <DeviceScan />

      <section className="content-section">
        <SectionHeading
          eyebrow="OBSERVED CONNECTIONS"
          title="Traffic event list"
          description="This view is based on detected events, not a live packet stream."
        />
        <ThreatTable alerts={alerts} openAlert={openAlert} selectedId={selectedAlert?.id} />
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
  const [results, setResults] = useState({});
  const [runningId, setRunningId] = useState(null);

  function runAnalysis(alert) {
    setRunningId(alert.id);
    setTimeout(() => {
      setResults((current) => ({ ...current, [alert.id]: generateAnalysis(alert) }));
      setRunningId((current) => (current === alert.id ? null : current));
    }, 1800);
  }

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
          Choose an event, run the analysis, then ask follow-up questions.
          In this demo the AI output is simulated; a connected backend
          would supply real analysis.
        </p>
      </div>

      <section className="content-section">
        <SectionHeading eyebrow="AVAILABLE EVENTS" title="Choose an investigation" />
        <ThreatTable alerts={alerts} openAlert={openAlert} selectedId={selectedAlert?.id} />
      </section>

      {selectedAlert && (
        <section className="content-section">
          <SectionHeading
            eyebrow="INVESTIGATION RESULT"
            title={selectedAlert.attack_type}
          />
          <AnalysisRunner
            alert={selectedAlert}
            result={results[selectedAlert.id]}
            running={runningId === selectedAlert.id}
            onRun={() => runAnalysis(selectedAlert)}
            onDownload={() =>
              downloadFile(
                `${selectedAlert.id}-report.md`,
                buildReport(selectedAlert, results[selectedAlert.id]),
                "text/markdown"
              )
            }
          />
          <InvestigationPanel alert={selectedAlert} />
          <AiAssistant key={selectedAlert.id} alert={selectedAlert} />
        </section>
      )}
    </>
  );
}

function StatCard({ label, value, note, variant, onClick }) {
  const clickable = typeof onClick === "function";

  return (
    <article
      className={`stat-card stat-${variant} ${clickable ? "stat-clickable" : ""}`}
      {...(clickable
        ? {
            role: "button",
            tabIndex: 0,
            onClick,
            onKeyDown: (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onClick();
              }
            },
          }
        : {})}
    >
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-note">
        {note}
        {clickable && <span className="stat-link"> · View ↗</span>}
      </div>
    </article>
  );
}

const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const TABLE_COLUMNS = [
  { key: "attack_type", label: "EVENT" },
  { key: "source_ip", label: "SOURCE IP" },
  { key: "destination_ip", label: "DESTINATION IP" },
  { key: "severity", label: "SEVERITY" },
  { key: "status", label: "STATUS" },
  { key: "timestamp", label: "TIME" },
];

function sortValue(alert, key) {
  if (key === "severity") return SEVERITY_RANK[alert.severity] || 0;
  if (key === "timestamp") return new Date(alert.timestamp).getTime() || 0;
  return String(alert[key] ?? "").toLowerCase();
}

function ThreatTable({ alerts, openAlert, selectedId, pageSize = 6 }) {
  const [sort, setSort] = useState({ key: null, direction: "asc" });
  const [page, setPage] = useState(0);

  const sorted = useMemo(() => {
    if (!sort.key) return alerts;
    const factor = sort.direction === "asc" ? 1 : -1;
    return [...alerts].sort((a, b) => {
      const left = sortValue(a, sort.key);
      const right = sortValue(b, sort.key);
      return left < right ? -factor : left > right ? factor : 0;
    });
  }, [alerts, sort]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = sorted.slice(currentPage * pageSize, currentPage * pageSize + pageSize);

  function toggleSort(key) {
    setPage(0);
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
        : { key, direction: key === "timestamp" || key === "severity" ? "desc" : "asc" }
    );
  }

  if (!alerts.length) {
    return (
      <div className="empty-state">
        <h3>No matching events</h3>
        <p>Try changing your search or filters.</p>
      </div>
    );
  }

  return (
    <>
      <div className="table-wrap">
        <table className="threat-table">
          <thead>
            <tr>
              {TABLE_COLUMNS.map((column) => {
                const active = sort.key === column.key;
                return (
                  <th
                    key={column.key}
                    aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}
                  >
                    <button className="th-sort" onClick={() => toggleSort(column.key)}>
                      {column.label}
                      <span aria-hidden="true">
                        {active ? (sort.direction === "asc" ? " ▲" : " ▼") : " ↕"}
                      </span>
                    </button>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {visible.map((alert) => (
              <tr key={alert.id} className={alert.id === selectedId ? "row-selected" : ""}>
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

      {pageCount > 1 && (
        <div className="pagination">
          <span>
            Page {currentPage + 1} of {pageCount}
          </span>
          <div>
            <button
              className="chip-button"
              onClick={() => setPage(currentPage - 1)}
              disabled={currentPage === 0}
            >
              ← Previous
            </button>
            <button
              className="chip-button"
              onClick={() => setPage(currentPage + 1)}
              disabled={currentPage >= pageCount - 1}
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </>
  );
}

function InvestigationPanel({ alert }) {
  return (
    <div className="investigation-layout" id="investigation">
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

        <AlertActions key={alert.id} alert={alert} />
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