import {
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import {
  PROTOCOL_MIX,
  SCAN_DEVICES,
  SUGGESTED_QUESTIONS,
  TOP_TALKERS,
  TRAFFIC_RANGES,
  aiReply,
  makeLiveSeed,
  makeTrafficSeries,
} from "./dummyData.js";
import { ActionsContext } from "./shared.js";

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

function useDismiss(ref, open, close) {
  useEffect(() => {
    if (!open) return undefined;

    const onPointer = (event) => {
      if (ref.current && !ref.current.contains(event.target)) close();
    };
    const onKey = (event) => {
      if (event.key === "Escape") close();
    };

    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [ref, open, close]);
}

/* ------------------------------------------------------------------ */
/* Charts                                                              */
/* ------------------------------------------------------------------ */

export function TrafficChart({ values, labels, unit = "pkts/s" }) {
  const gradientId = useId().replace(/:/g, "");
  const [hover, setHover] = useState(null);

  const width = 600;
  const height = 180;
  const pad = 8;
  const max = Math.max(...values) * 1.1;

  const points = values.map((value, i) => [
    (i / (values.length - 1)) * width,
    height - (value / max) * (height - pad * 2) - pad,
  ]);
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");

  const index = hover ?? values.length - 1;

  function onMove(event) {
    const rect = event.currentTarget.getBoundingClientRect();
    const ratio = (event.clientX - rect.left) / rect.width;
    setHover(Math.max(0, Math.min(values.length - 1, Math.round(ratio * (values.length - 1)))));
  }

  return (
    <div className="chart">
      <div className="chart-readout">
        <strong>{Math.round(values[index]).toLocaleString()}</strong>
        <span>{unit}</span>
        <em>{labels[index]}</em>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label="Traffic over time"
      >
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#43f58a" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#43f58a" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((ratio) => (
          <line
            key={ratio}
            x1="0"
            x2={width}
            y1={height * ratio}
            y2={height * ratio}
            className="chart-gridline"
          />
        ))}
        <polygon points={`0,${height} ${line} ${width},${height}`} fill={`url(#${gradientId})`} />
        <polyline points={line} className="chart-line" />
        {hover !== null && (
          <line
            x1={points[index][0]}
            x2={points[index][0]}
            y1="0"
            y2={height}
            className="chart-cursor"
          />
        )}
      </svg>
    </div>
  );
}

export function TrafficPanel() {
  const [range, setRange] = useState("24H");
  const { values, labels } = makeTrafficSeries(range);
  const peak = Math.round(Math.max(...values));
  const average = Math.round(values.reduce((a, b) => a + b, 0) / values.length);

  return (
    <section className="panel">
      <div className="panel-head">
        <span className="panel-title">NETWORK TRAFFIC</span>
        <div className="segmented" role="tablist" aria-label="Time range">
          {TRAFFIC_RANGES.map((item) => (
            <button
              key={item}
              role="tab"
              aria-selected={range === item}
              className={range === item ? "segmented-active" : ""}
              onClick={() => setRange(item)}
            >
              {item}
            </button>
          ))}
        </div>
      </div>
      <TrafficChart values={values} labels={labels} />
      <div className="panel-foot">
        <span>PEAK <strong>{peak.toLocaleString()}</strong></span>
        <span>AVERAGE <strong>{average.toLocaleString()}</strong></span>
        <span>SAMPLE DATA</span>
      </div>
    </section>
  );
}

export function SeverityBreakdown({ alerts, onSelect }) {
  const levels = ["Critical", "High", "Medium", "Low"];
  const total = alerts.length || 1;

  return (
    <div className="breakdown">
      {levels.map((level) => {
        const count = alerts.filter((a) => a.severity === level).length;
        return (
          <button
            key={level}
            className="breakdown-row"
            onClick={() => onSelect(level)}
            title={`View ${level} alerts`}
          >
            <span className="breakdown-label">{level}</span>
            <span className="breakdown-track">
              <span
                className={`breakdown-fill severity-fill-${level.toLowerCase()}`}
                style={{ width: `${(count / total) * 100}%` }}
              />
            </span>
            <span className="breakdown-count">{count}</span>
          </button>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Network page                                                        */
/* ------------------------------------------------------------------ */

export function LiveTrafficPanel() {
  const { notify } = useContext(ActionsContext);
  const [values, setValues] = useState(() => makeLiveSeed(40));
  const [running, setRunning] = useState(true);

  useEffect(() => {
    if (!running) return undefined;

    const timer = setInterval(() => {
      const jitter = Math.random();
      setValues((previous) => {
        const last = previous[previous.length - 1];
        const next = Math.max(120, Math.round(last * 0.6 + 420 * 0.4 + (jitter - 0.5) * 140));
        return [...previous.slice(1), next];
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [running]);

  function simulateSpike() {
    setValues((previous) => [...previous.slice(3), 980, 1340, 1210]);
    notify("Simulated traffic spike added to the live feed.");
  }

  const labels = values.map((_, i) => `${values.length - 1 - i}s ago`);
  const current = values[values.length - 1];
  const peak = Math.max(...values);

  return (
    <section className="panel">
      <div className="panel-head">
        <span className="panel-title">
          LIVE TRAFFIC
          <span className={`live-pill ${running ? "" : "live-pill-paused"}`}>
            <i /> {running ? "LIVE" : "PAUSED"}
          </span>
        </span>
        <div className="panel-actions">
          <button className="button-secondary button-small" onClick={() => setRunning((v) => !v)}>
            {running ? "Pause" : "Resume"}
          </button>
          <button className="button-secondary button-small" onClick={simulateSpike}>
            Simulate spike
          </button>
          <button
            className="button-secondary button-small"
            onClick={() => {
              setValues(makeLiveSeed(40));
              notify("Live feed reset.");
            }}
          >
            Reset
          </button>
        </div>
      </div>
      <TrafficChart values={values} labels={labels} />
      <div className="panel-foot">
        <span>CURRENT <strong>{current.toLocaleString()} pkts/s</strong></span>
        <span>THROUGHPUT <strong>{(current * 0.012).toFixed(1)} Mbps</strong></span>
        <span>PEAK <strong>{peak.toLocaleString()}</strong></span>
      </div>
    </section>
  );
}

export function ProtocolMix() {
  const [active, setActive] = useState(null);

  return (
    <section className="panel">
      <div className="panel-head">
        <span className="panel-title">PROTOCOL MIX</span>
      </div>
      <div className="mix-bar">
        {PROTOCOL_MIX.map((item) => (
          <span
            key={item.name}
            className={active && active !== item.name ? "mix-dim" : ""}
            style={{ width: `${item.value}%`, background: item.color }}
            onMouseEnter={() => setActive(item.name)}
            onMouseLeave={() => setActive(null)}
            title={`${item.name} ${item.value}%`}
          />
        ))}
      </div>
      <ul className="mix-legend">
        {PROTOCOL_MIX.map((item) => (
          <li
            key={item.name}
            className={active === item.name ? "mix-active" : ""}
            onMouseEnter={() => setActive(item.name)}
            onMouseLeave={() => setActive(null)}
          >
            <i style={{ background: item.color }} />
            <span>{item.name}</span>
            <strong>{item.value}%</strong>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function TopTalkers() {
  const { blocked, blockIp, unblockIp } = useContext(ActionsContext);

  return (
    <section className="content-section">
      <div className="panel-title panel-title-lone">TOP TALKERS</div>
      <div className="table-wrap">
        <table className="threat-table">
          <thead>
            <tr>
              <th>IP ADDRESS</th>
              <th>ROLE</th>
              <th>CONNECTIONS</th>
              <th>DATA (MB)</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {TOP_TALKERS.map((talker) => {
              const isBlocked = blocked.includes(talker.ip);
              return (
                <tr key={talker.ip}>
                  <td className="mono"><strong>{talker.ip}</strong></td>
                  <td>{talker.role}</td>
                  <td className="mono">{talker.connections.toLocaleString()}</td>
                  <td className="mono">{talker.megabytes.toLocaleString()}</td>
                  <td>
                    <button
                      className={`chip-button ${isBlocked ? "chip-danger" : ""}`}
                      onClick={() => (isBlocked ? unblockIp(talker.ip) : blockIp(talker.ip))}
                    >
                      {isBlocked ? "Blocked · Unblock" : "Block"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function BlocklistPanel() {
  const { blocked, blockIp, unblockIp, clearBlocked, notify } = useContext(ActionsContext);
  const [value, setValue] = useState("");
  const [error, setError] = useState("");

  function submit(event) {
    event.preventDefault();
    const ip = value.trim();

    if (!IPV4.test(ip)) {
      setError("Enter a valid IPv4 address, e.g. 203.0.113.7");
      return;
    }
    if (blocked.includes(ip)) {
      setError(`${ip} is already blocked.`);
      return;
    }
    blockIp(ip);
    setValue("");
    setError("");
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <span className="panel-title">BLOCKLIST · {blocked.length}</span>
        {blocked.length > 0 && (
          <button
            className="text-button"
            onClick={() => {
              clearBlocked();
              notify("Blocklist cleared.");
            }}
          >
            Clear all
          </button>
        )}
      </div>

      <form className="blocklist-form" onSubmit={submit}>
        <input
          className="search-input"
          placeholder="Block an IP address"
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            setError("");
          }}
          aria-label="IP address to block"
        />
        <button className="button-primary button-small" type="submit">
          Block
        </button>
      </form>
      {error && <p className="form-error">{error}</p>}

      {blocked.length ? (
        <ul className="blocklist">
          {blocked.map((ip) => (
            <li key={ip}>
              <span className="mono">{ip}</span>
              <button className="text-button" onClick={() => unblockIp(ip)}>
                Unblock
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="panel-empty">No addresses are blocked. This is a simulation: nothing is sent to a firewall.</p>
      )}
    </section>
  );
}

export function DeviceScan() {
  const [scan, setScan] = useState({ phase: "idle", progress: 0 });

  useEffect(() => {
    if (scan.phase !== "scanning") return undefined;

    const timer = setInterval(() => {
      setScan((current) =>
        current.progress >= 100
          ? { phase: "done", progress: 100 }
          : { ...current, progress: Math.min(100, current.progress + 8) }
      );
    }, 150);

    return () => clearInterval(timer);
  }, [scan.phase]);

  return (
    <section className="content-section">
      <div className="panel-head panel-head-lone">
        <span className="panel-title">NETWORK DEVICES</span>
        <button
          className="button-primary button-small"
          disabled={scan.phase === "scanning"}
          onClick={() => setScan({ phase: "scanning", progress: 0 })}
        >
          {scan.phase === "scanning" ? "Scanning..." : scan.phase === "done" ? "Rescan network" : "Run network scan"}
        </button>
      </div>

      {scan.phase === "idle" && (
        <div className="empty-state">
          <h3>No scan results yet</h3>
          <p>Run a scan to discover devices on the network (sample data).</p>
        </div>
      )}

      {scan.phase === "scanning" && (
        <div className="scan-progress">
          <div className="splash-bar">
            <div className="scan-fill" style={{ width: `${scan.progress}%` }} />
          </div>
          <span>Scanning 192.168.1.0/24... {scan.progress}%</span>
        </div>
      )}

      {scan.phase === "done" && (
        <div className="table-wrap">
          <table className="threat-table">
            <thead>
              <tr>
                <th>DEVICE</th>
                <th>IP ADDRESS</th>
                <th>TYPE</th>
                <th>OPEN PORTS</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {SCAN_DEVICES.map((device) => (
                <tr key={device.ip}>
                  <td><strong>{device.name}</strong></td>
                  <td className="mono">{device.ip}</td>
                  <td>{device.type}</td>
                  <td className="mono">{device.ports}</td>
                  <td>
                    <span className={`status-label ${device.status === "Unrecognised" ? "status-warn" : ""}`}>
                      {device.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Threat actions                                                      */
/* ------------------------------------------------------------------ */

export function AlertActions({ alert }) {
  const { updateStatus, blocked, blockIp, unblockIp, addNote, copyText } =
    useContext(ActionsContext);
  const [note, setNote] = useState("");
  const isBlocked = blocked.includes(alert.source_ip);

  const statusActions = [
    ["Investigating", "Start investigation"],
    ["Under review", "Mark under review"],
    ["Escalated", "Escalate"],
    ["Resolved", "Resolve"],
  ];

  function submitNote(event) {
    event.preventDefault();
    if (!note.trim()) return;
    addNote(alert, note.trim());
    setNote("");
  }

  return (
    <div className="actions-block">
      <div className="detail-overline">RESPONSE ACTIONS</div>
      <div className="action-row">
        {statusActions.map(([status, label]) => (
          <button
            key={status}
            className="chip-button"
            disabled={alert.status === status}
            onClick={() => updateStatus(alert, status)}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="action-row">
        <button
          className={`chip-button ${isBlocked ? "chip-danger" : ""}`}
          onClick={() => (isBlocked ? unblockIp(alert.source_ip) : blockIp(alert.source_ip))}
        >
          {isBlocked ? `Unblock ${alert.source_ip}` : `Block ${alert.source_ip}`}
        </button>
        <button className="chip-button" onClick={() => copyText(alert.source_ip, "Source IP copied.")}>
          Copy source IP
        </button>
        <button className="chip-button" onClick={() => copyText(alert.destination_ip, "Destination IP copied.")}>
          Copy destination IP
        </button>
      </div>

      <div className="detail-overline detail-subheading">ANALYST NOTES</div>
      {alert.notes?.length ? (
        <ul className="notes-list">
          {alert.notes.map((item, i) => (
            <li key={`${item.time}-${i}`}>
              <small>{item.time}</small>
              <span>{item.text}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="panel-empty">No notes yet.</p>
      )}
      <form className="blocklist-form" onSubmit={submitNote}>
        <input
          className="search-input"
          placeholder="Add a note about this alert"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          aria-label="Analyst note"
        />
        <button className="button-secondary button-small" type="submit" disabled={!note.trim()}>
          Add note
        </button>
      </form>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* AI analysis                                                         */
/* ------------------------------------------------------------------ */

export function AnalysisRunner({ alert, result, running, onRun, onDownload }) {
  return (
    <div className="runner">
      <div className="runner-head">
        <div>
          <div className="detail-overline">SIMULATED AI ANALYSIS</div>
          <h3>{alert.attack_type}</h3>
        </div>
        <div className="panel-actions">
          <button className="button-primary button-small" onClick={onRun} disabled={running}>
            {running ? "Analyzing..." : result ? "Re-run analysis" : "Run AI analysis"}
          </button>
          <button className="button-secondary button-small" onClick={onDownload}>
            Download report
          </button>
        </div>
      </div>

      {running && (
        <div className="runner-loading">
          <div className="splash-bar"><div className="runner-fill" /></div>
          <span>Correlating evidence and scoring risk...</span>
        </div>
      )}

      {!running && !result && (
        <p className="panel-empty">
          Run the analysis to generate a risk score and recommended steps. Results are simulated demo data.
        </p>
      )}

      {!running && result && (
        <div className="runner-result">
          <div className="risk-score">
            <strong>{result.riskScore}</strong>
            <span>RISK SCORE / 100</span>
          </div>
          <div>
            <p>{result.summary}</p>
            <ol className="runner-steps">
              {result.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <small>
              Generated {new Date(result.generatedAt).toLocaleTimeString()} · demo output
            </small>
          </div>
        </div>
      )}
    </div>
  );
}

export function AiAssistant({ alert }) {
  const [messages, setMessages] = useState([
    {
      from: "ai",
      text: `I'm looking at ${alert.attack_type} (${alert.id}). Ask me anything about it.`,
    },
  ]);
  const [input, setInput] = useState("");
  const [thinking, setThinking] = useState(false);
  const scroller = useRef(null);

  useEffect(() => {
    if (scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [messages, thinking]);

  function ask(question) {
    const text = question.trim();
    if (!text || thinking) return;

    setMessages((current) => [...current, { from: "user", text }]);
    setInput("");
    setThinking(true);

    setTimeout(() => {
      setMessages((current) => [...current, { from: "ai", text: aiReply(text, alert) }]);
      setThinking(false);
    }, 900);
  }

  return (
    <div className="assistant">
      <div className="detail-overline">ASK AEGIS · SIMULATED</div>

      <div className="assistant-log" ref={scroller} aria-live="polite">
        {messages.map((message, i) => (
          <div key={i} className={`bubble bubble-${message.from}`}>
            {message.text}
          </div>
        ))}
        {thinking && <div className="bubble bubble-ai bubble-thinking">Thinking...</div>}
      </div>

      <div className="action-row">
        {SUGGESTED_QUESTIONS.map((question) => (
          <button key={question} className="chip-button" onClick={() => ask(question)} disabled={thinking}>
            {question}
          </button>
        ))}
      </div>

      <form
        className="blocklist-form"
        onSubmit={(event) => {
          event.preventDefault();
          ask(input);
        }}
      >
        <input
          className="search-input"
          placeholder="Ask about this alert..."
          value={input}
          onChange={(event) => setInput(event.target.value)}
          aria-label="Question for the assistant"
        />
        <button className="button-primary button-small" type="submit" disabled={thinking || !input.trim()}>
          Send
        </button>
      </form>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Topbar menus                                                        */
/* ------------------------------------------------------------------ */

export function NotificationMenu({ notifications, setNotifications, onOpenAlert }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const close = () => setOpen(false);
  useDismiss(ref, open, close);

  const unread = notifications.filter((n) => !n.read).length;

  return (
    <div className="menu-wrap" ref={ref}>
      <button
        className="menu-trigger"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="true"
      >
        NOTIFICATIONS
        {unread > 0 && <span className="menu-badge">{unread}</span>}
      </button>

      {open && (
        <div className="menu-panel menu-panel-wide" role="menu">
          <div className="menu-head">
            <strong>Notifications</strong>
            <button
              className="text-button"
              disabled={!unread}
              onClick={() => setNotifications((list) => list.map((n) => ({ ...n, read: true })))}
            >
              Mark all read
            </button>
          </div>

          {notifications.length ? (
            <ul className="menu-list">
              {notifications.map((item) => (
                <li key={item.id} className={item.read ? "" : "menu-unread"}>
                  <button
                    className="menu-item"
                    onClick={() => {
                      setNotifications((list) =>
                        list.map((n) => (n.id === item.id ? { ...n, read: true } : n))
                      );
                      onOpenAlert(item.alertId);
                      close();
                    }}
                  >
                    <span>{item.text}</span>
                    <small>{item.time}</small>
                  </button>
                  <button
                    className="menu-dismiss"
                    aria-label="Dismiss notification"
                    onClick={() => setNotifications((list) => list.filter((n) => n.id !== item.id))}
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="menu-empty">You're all caught up.</p>
          )}

          {notifications.length > 0 && (
            <div className="menu-foot">
              <button className="text-button" onClick={() => setNotifications([])}>
                Clear all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Toggle({ label, hint, checked, onChange }) {
  return (
    <button
      className="menu-toggle"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
    >
      <span>
        {label}
        {hint && <small>{hint}</small>}
      </span>
      <span className={`switch ${checked ? "switch-on" : ""}`}><i /></span>
    </button>
  );
}

export function UserMenu({ autoRefresh, setAutoRefresh, compact, setCompact, onSignOut }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const close = () => setOpen(false);
  useDismiss(ref, open, close);

  return (
    <div className="menu-wrap" ref={ref}>
      <button
        className="menu-trigger user-label"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="true"
      >
        MJ / ADMIN <span aria-hidden="true">▾</span>
      </button>

      {open && (
        <div className="menu-panel" role="menu">
          <div className="menu-head">
            <strong>Preferences</strong>
          </div>
          <Toggle
            label="Auto-refresh alerts"
            hint="Every 5 seconds"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          <Toggle
            label="Compact tables"
            hint="Tighter row spacing"
            checked={compact}
            onChange={setCompact}
          />
          <div className="menu-foot">
            <button
              className="text-button"
              onClick={() => {
                close();
                onSignOut();
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function SignedOutScreen({ onSignIn }) {
  return (
    <div className="signed-out">
      <div className="signed-out-card">
        <div className="brand-symbol">A</div>
        <h2>You've been signed out</h2>
        <p>This is a demo sign-out. No account or session is involved.</p>
        <button className="button-primary" onClick={onSignIn}>
          Sign back in
        </button>
      </div>
    </div>
  );
}