import { useMemo, useState } from "react";
import { useGreenhouseData } from "./useGreenhouseData";

function formatNumber(value, digits = 1) {
  const numeric = Number(value);

  if (!Number.isFinite(numeric)) {
    return "—";
  }

  return numeric.toFixed(digits);
}

function formatDuration(milliseconds) {
  const value = Number(milliseconds);

  if (!Number.isFinite(value)) {
    return "—";
  }

  if (value < 1000) {
    return `${Math.round(value)} ms`;
  }

  const seconds = Math.floor(value / 1000);

  if (seconds < 60) {
    return `${seconds}s`;
  }

  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function timeLabel(timestamp) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function StatusPill({ value, kind = "neutral" }) {
  return (
    <span className={`status-pill status-pill--${kind}`}>
      <span className="status-pill__dot" />
      {value}
    </span>
  );
}

function MetricCard({
  label,
  value,
  unit,
  hint,
  tone = "default",
  children
}) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__label">{label}</div>
      <div className="metric-card__value-row">
        <div className="metric-card__value">{value}</div>
        {unit && <div className="metric-card__unit">{unit}</div>}
      </div>
      {hint && <div className="metric-card__hint">{hint}</div>}
      {children}
    </article>
  );
}

function Gauge({
  value,
  label,
  threshold = 0.5,
  formatter = (item) => `${Math.round(item * 100)}%`
}) {
  const safe = Math.max(0, Math.min(1, Number(value) || 0));
  const degrees = safe * 180;

  return (
    <div className="gauge">
      <div
        className="gauge__arc"
        style={{
          background: `conic-gradient(
            from 270deg,
            var(--success) 0deg,
            ${safe >= threshold ? "var(--danger)" : "var(--accent)"} ${degrees}deg,
            rgba(255,255,255,.08) ${degrees}deg,
            rgba(255,255,255,.08) 180deg,
            transparent 180deg
          )`
        }}
      >
        <div className="gauge__inner">
          <strong>{formatter(safe)}</strong>
          <span>{label}</span>
        </div>
      </div>
      <div className="gauge__scale">
        <span>0</span>
        <span>Threshold {Math.round(threshold * 100)}%</span>
        <span>100</span>
      </div>
    </div>
  );
}

function Sparkline({ points, valueKey, ariaLabel }) {
  const width = 520;
  const height = 150;
  const padding = 12;
  const values = points
    .map((point) => Number(point[valueKey]))
    .filter(Number.isFinite);

  if (values.length < 2) {
    return <div className="empty-chart">Waiting for history…</div>;
  }

  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const range = Math.max(maximum - minimum, 0.0001);

  const path = values
    .map((value, index) => {
      const x =
        padding
        + (index / (values.length - 1))
          * (width - padding * 2);
      const y =
        height
        - padding
        - ((value - minimum) / range)
          * (height - padding * 2);

      return `${index === 0 ? "M" : "L"} ${x} ${y}`;
    })
    .join(" ");

  const area = `${path} L ${width - padding} ${height - padding} L ${padding} ${height - padding} Z`;

  return (
    <svg
      className="sparkline"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={ariaLabel}
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id={`area-${valueKey}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity=".32" />
          <stop offset="100%" stopColor="currentColor" stopOpacity=".02" />
        </linearGradient>
      </defs>
      <path
        className="sparkline__area"
        d={area}
        fill={`url(#area-${valueKey})`}
      />
      <path className="sparkline__line" d={path} />
    </svg>
  );
}

function Panel({ title, subtitle, action, children, className = "" }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel__header">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function SecurityItem({ label, value, state = "neutral", meta }) {
  return (
    <div className="security-item">
      <div>
        <span className="security-item__label">{label}</span>
        {meta && <small>{meta}</small>}
      </div>
      <StatusPill value={value} kind={state} />
    </div>
  );
}

function EventTable({ events }) {
  return (
    <div className="event-list">
      {events.length === 0 && (
        <div className="event-list__empty">No events received.</div>
      )}

      {events.map((event) => (
        <div className="event-row" key={event.id}>
          <div className={`event-row__marker event-row__marker--${event.severity}`} />
          <div className="event-row__content">
            <div className="event-row__top">
              <strong>{event.type}</strong>
              <time>{timeLabel(event.time)}</time>
            </div>
            <p>{event.message}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function App() {
  const { data, error, loading, mode } = useGreenhouseData();
  const [selectedChart, setSelectedChart] = useState("temperature");

  const stateTone = {
    NORMAL: "success",
    LOCKED: "warning",
    LOCKDOWN: "danger"
  }[data.systemState] || "neutral";

  const tinyMl = data.security.tinyml;
  const rfid = data.security.rfid;
  const session = data.security.session;
  const keys = data.security.keys;

  const chartMeta = useMemo(
    () => ({
      temperature: {
        label: "Temperature",
        unit: "°C",
        value:
          data.history.at(-1)?.temperature
          ?? data.sensors.temperature
      },
      humidity: {
        label: "Humidity",
        unit: "%",
        value:
          data.history.at(-1)?.humidity
          ?? data.sensors.humidity
      },
      soilPercent: {
        label: "Soil moisture",
        unit: "%",
        value:
          data.history.at(-1)?.soilPercent
          ?? data.sensors.soilPercent
      },
      anomalyProbability: {
        label: "TinyML anomaly probability",
        unit: "%",
        value:
          (data.history.at(-1)?.anomalyProbability
          ?? tinyMl.probability) * 100
      }
    }),
    [data.history, data.sensors, tinyMl.probability]
  );

  const activeChart = chartMeta[selectedChart];

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand__mark">C1</div>
          <div>
            <span className="eyebrow">Attack-Resilient IoT Smart Greenhouse</span>
            <h1>Edge Security Dashboard</h1>
          </div>
        </div>

        <div className="topbar__actions">
          <StatusPill
            value={mode === "LIVE" ? "Live data" : "Demo mode"}
            kind={mode === "LIVE" ? "success" : "warning"}
          />
          <StatusPill
            value={data.connection === "online" ? "Node online" : "Node offline"}
            kind={data.connection === "online" ? "success" : "danger"}
          />
        </div>
      </header>

      <main className="dashboard">
        <section className="hero panel">
          <div>
            <span className="eyebrow">Component 01 · Edge Node</span>
            <div className="hero__title-row">
              <h2>{data.nodeId}</h2>
              <StatusPill value={data.systemState} kind={stateTone} />
            </div>
            <p>
              Secure local sensing, protected RFID authentication,
              TinyML anomaly detection, actuator fail-safe control and
              runtime-key zeroization.
            </p>
          </div>

          <div className="hero__meta">
            <div>
              <span>Scenario</span>
              <strong>{data.scenario}</strong>
            </div>
            <div>
              <span>Last update</span>
              <strong>{timeLabel(data.timestamp)}</strong>
            </div>
          </div>
        </section>

        {error && (
          <div className="alert alert--danger">
            <strong>Live-data error:</strong> {error}
          </div>
        )}

        {loading && (
          <div className="alert">
            Loading greenhouse telemetry…
          </div>
        )}

        <section className="metric-grid">
          <MetricCard
            label="Temperature"
            value={formatNumber(data.sensors.temperature)}
            unit="°C"
            hint="Fan ON ≥ 32°C · OFF ≤ 30.5°C"
            tone={data.sensors.temperature >= 32 ? "warning" : "default"}
          />
          <MetricCard
            label="Humidity"
            value={formatNumber(data.sensors.humidity)}
            unit="%"
            hint="DHT22 environmental reading"
          />
          <MetricCard
            label="Light intensity"
            value={formatNumber(data.sensors.light)}
            unit="lux"
            hint="BH1750 · I²C address 0x23"
            tone={data.sensors.light < 4 ? "danger" : "default"}
          />
          <MetricCard
            label="Soil moisture"
            value={formatNumber(data.sensors.soilPercent, 0)}
            unit="%"
            hint={`Raw ${data.sensors.soilRaw} · ${
              data.sensors.soilValid ? "valid" : "open circuit / implausible"
            }`}
            tone={data.sensors.soilValid ? "default" : "danger"}
          />
        </section>

        <section className="dashboard-grid dashboard-grid--wide-left">
          <Panel
            title="Live environmental trend"
            subtitle={`${activeChart.label}: ${formatNumber(activeChart.value)}${activeChart.unit}`}
            action={
              <select
                className="select-control"
                value={selectedChart}
                onChange={(event) => setSelectedChart(event.target.value)}
              >
                <option value="temperature">Temperature</option>
                <option value="humidity">Humidity</option>
                <option value="soilPercent">Soil moisture</option>
                <option value="anomalyProbability">TinyML risk</option>
              </select>
            }
          >
            <Sparkline
              points={data.history}
              valueKey={selectedChart}
              ariaLabel={`${activeChart.label} trend`}
            />
            <div className="chart-footer">
              <span>{timeLabel(data.history[0]?.time || data.timestamp)}</span>
              <span>Latest {timeLabel(data.timestamp)}</span>
            </div>
          </Panel>

          <Panel
            title="Actuator safety"
            subtitle="Active-low relay modules · HIGH is safe OFF"
          >
            <div className="actuator-stack">
              <div className="actuator-row">
                <div>
                  <span>Pump</span>
                  <strong>{data.actuators.pump ? "ON" : "OFF"}</strong>
                </div>
                <StatusPill
                  value={data.actuators.pump ? "LOW / ON" : "HIGH / OFF"}
                  kind={data.actuators.pump ? "warning" : "success"}
                />
              </div>
              <div className="actuator-row">
                <div>
                  <span>Pump runtime</span>
                  <strong>{formatDuration(data.actuators.pumpRuntimeMs)}</strong>
                </div>
                <small>Max 5 seconds</small>
              </div>
              <div className="actuator-row">
                <div>
                  <span>Fan</span>
                  <strong>{data.actuators.fan ? "ON" : "OFF"}</strong>
                </div>
                <StatusPill
                  value={data.actuators.fan ? "LOW / ON" : "HIGH / OFF"}
                  kind={data.actuators.fan ? "warning" : "success"}
                />
              </div>
              <div className="actuator-row">
                <div>
                  <span>Fan runtime</span>
                  <strong>{formatDuration(data.actuators.fanRuntimeMs)}</strong>
                </div>
                <small>Included in TinyML features</small>
              </div>
            </div>
          </Panel>
        </section>

        <section className="dashboard-grid">
          <Panel
            title="Environmental TinyML"
            subtitle="Five-feature Random Forest · three-confirmation gate"
          >
            <Gauge
              value={tinyMl.probability}
              label={tinyMl.prediction ? "ANOMALY" : "NORMAL"}
            />
            <div className="risk-meta">
              <span>
                Confirmations
                <strong>
                  {tinyMl.confirmations}/{tinyMl.requiredConfirmations}
                </strong>
              </span>
              <span>
                Inference
                <strong>{tinyMl.inferenceLatencyUs} µs</strong>
              </span>
            </div>
          </Panel>

          <Panel
            title="RFID timing risk"
            subtitle="Supporting signal only · no active security action"
          >
            <Gauge
              value={rfid.timingRiskProbability}
              threshold={0.75}
              label={rfid.timingRiskFlag ? "ELEVATED" : "NOT ELEVATED"}
            />
            <div className="risk-meta">
              <span>
                Sector auth
                <strong>{rfid.authLatencyUs} µs</strong>
              </span>
              <span>
                Pipeline
                <strong>{rfid.pipelineLatencyUs} µs</strong>
              </span>
            </div>
          </Panel>

          <Panel
            title="Authenticated session"
            subtitle="Incident correlation to credential session"
          >
            <div className="session-card">
              <StatusPill
                value={session.active ? "SESSION ACTIVE" : "NO SESSION"}
                kind={session.active ? "success" : "neutral"}
              />
              <div className="session-card__id">
                <span>Session ID</span>
                <strong>#{session.id}</strong>
              </div>
              <div className="session-card__row">
                <span>Credential UID</span>
                <strong>{rfid.uid}</strong>
              </div>
              <div className="session-card__row">
                <span>Final result</span>
                <strong>{rfid.result}</strong>
              </div>
              <div className="session-card__row">
                <span>Session age</span>
                <strong>{formatDuration(session.ageMs)}</strong>
              </div>
            </div>
          </Panel>
        </section>

        <section className="dashboard-grid dashboard-grid--wide-right">
          <Panel
            title="Security state"
            subtitle="Deterministic controls remain primary"
          >
            <div className="security-list">
              <SecurityItem
                label="Enclosure tamper"
                value={data.security.tamper ? "BREACHED" : data.security.enclosure}
                state={data.security.tamper ? "danger" : "success"}
                meta="GPIO13 reed switch"
              />
              <SecurityItem
                label="Runtime NwkSKey"
                value={keys.nwkSKey}
                state={keys.nwkSKey === "ZEROIZED" ? "danger" : "success"}
                meta="SRAM runtime container"
              />
              <SecurityItem
                label="Runtime RFID Key A"
                value={keys.rfidKeyA}
                state={keys.rfidKeyA === "ZEROIZED" ? "danger" : "success"}
                meta="Protected Sector 4 authentication"
              />
              <SecurityItem
                label="Zeroization verification"
                value={keys.zeroization}
                state={
                  keys.zeroization === "PASSED"
                    ? "success"
                    : keys.zeroization === "FAILED"
                      ? "danger"
                      : "neutral"
                }
                meta="Required after tamper or confirmed hard lockdown"
              />
            </div>
          </Panel>

          <Panel
            title="Security event timeline"
            subtitle="Latest edge-node events"
          >
            <EventTable events={data.events} />
          </Panel>
        </section>

        <Panel
          title="Component 1 security coverage"
          subtitle="Prototype functions currently represented in the dashboard"
        >
          <div className="coverage-grid">
            {[
              ["Protected RFID Sector 4", "Implemented"],
              ["Physical tamper response", "Validated"],
              ["Runtime key zeroization", "Validated"],
              ["Sensor manipulation detection", "Validated"],
              ["Actuator misuse detection", "Validated"],
              ["TinyML hard lockdown", "Validated"],
              ["Authenticated-session attribution", "Validated"],
              ["RFID timing signal", "Support only"],
              ["Real-world final accuracy", "Pending real data"]
            ].map(([label, value]) => (
              <div className="coverage-item" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </Panel>
      </main>

      <footer className="footer">
        <span>Component 01 · ESP32 Edge Security Node</span>
        <span>
          {mode === "LIVE"
            ? "Firebase REST integration enabled"
            : "Demo stream active · configure .env for live Firebase data"}
        </span>
      </footer>
    </div>
  );
}

export default App;
