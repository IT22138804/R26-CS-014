import { useMemo, useState } from "react";
import { useGreenhouseData } from "./useGreenhouseData";

const NAV_ITEMS = [
  ["overview", "Overview", "01"],
  ["insider", "Insider Misuse", "02"],
  ["rfid", "RFID & Clone", "03"],
  ["keys", "NwkSKey & Keys", "04"],
  ["tinyml", "TinyML & Lockdown", "05"],
  ["plant", "Sensors & Actuators", "06"],
  ["evidence", "Tests & Evidence", "07"],
  ["events", "Events & Forensics", "08"]
];

function formatNumber(value, digits = 1) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(digits) : "—";
}

function formatPercent(value, digits = 1) {
  return `${formatNumber(Number(value) * 100, digits)}%`;
}

function formatDuration(milliseconds) {
  const numeric = Number(milliseconds);

  if (!Number.isFinite(numeric)) {
    return "—";
  }

  if (numeric < 1000) {
    return `${Math.round(numeric)} ms`;
  }

  const seconds = Math.floor(numeric / 1000);

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

function SectionHeader({ eyebrow, title, description, right }) {
  return (
    <div className="section-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {right && <div className="section-header__right">{right}</div>}
    </div>
  );
}

function Panel({ title, subtitle, children, className = "", action }) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <div className="panel__header">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

function MetricCard({
  label,
  value,
  unit,
  hint,
  tone = "default",
  footer
}) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__label">{label}</div>
      <div className="metric-card__value-row">
        <div className="metric-card__value">{value}</div>
        {unit && <div className="metric-card__unit">{unit}</div>}
      </div>
      {hint && <div className="metric-card__hint">{hint}</div>}
      {footer && <div className="metric-card__footer">{footer}</div>}
    </article>
  );
}

function DetailRow({ label, value, tone, mono = false }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong
        className={[
          mono ? "mono" : "",
          tone ? `text-${tone}` : ""
        ].filter(Boolean).join(" ")}
      >
        {value}
      </strong>
    </div>
  );
}

function ProgressBar({ value, max = 1, tone = "accent", label }) {
  const percentage = Math.max(
    0,
    Math.min(100, (Number(value) / Number(max || 1)) * 100)
  );

  return (
    <div className="progress-block">
      {label && (
        <div className="progress-block__label">
          <span>{label}</span>
          <strong>{formatNumber(percentage, 1)}%</strong>
        </div>
      )}
      <div className="progress">
        <span
          className={`progress__bar progress__bar--${tone}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

function Gauge({ value, label, threshold = 0.5 }) {
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
          <strong>{formatPercent(safe, 1)}</strong>
          <span>{label}</span>
        </div>
      </div>
      <div className="gauge__scale">
        <span>0%</span>
        <span>Threshold {formatPercent(threshold, 0)}</span>
        <span>100%</span>
      </div>
    </div>
  );
}

function Sparkline({ points, valueKey, ariaLabel }) {
  const width = 700;
  const height = 220;
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
          <stop offset="0%" stopColor="currentColor" stopOpacity=".34" />
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

function Timeline({ items }) {
  return (
    <div className="timeline">
      {items.map((item) => (
        <div className="timeline__item" key={item.id}>
          <div className={`timeline__dot timeline__dot--${item.severity}`} />
          <div className="timeline__content">
            <div className="timeline__top">
              <strong>{item.type}</strong>
              <time>{timeLabel(item.time)}</time>
            </div>
            <p>{item.message}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function FeatureList({ items }) {
  return (
    <div className="feature-list">
      {items.map((item, index) => (
        <div className="feature-list__item" key={item}>
          <span>{index}</span>
          <strong>{item}</strong>
        </div>
      ))}
    </div>
  );
}

function TestTable({ rows }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Area</th>
            <th>Test</th>
            <th>Status</th>
            <th>Evidence</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const kind = row.status === "PASSED"
              ? "success"
              : row.status === "PARTIAL" || row.status === "PIPELINE ONLY"
                ? "warning"
                : "neutral";

            return (
              <tr key={`${row.category}-${row.test}`}>
                <td>{row.category}</td>
                <td>{row.test}</td>
                <td>
                  <StatusPill value={row.status} kind={kind} />
                </td>
                <td>{row.evidence}</td>
                <td>{row.source}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function App() {
  const { data, error, loading, mode } = useGreenhouseData();
  const [activeView, setActiveView] = useState("overview");
  const [selectedChart, setSelectedChart] = useState("temperature");

  const rfid = data.security.rfid;
  const tinyml = data.security.tinyml;
  const insider = data.security.insiderMisuse;
  const keys = data.security.keys;
  const session = data.security.session;
  const lockdown = data.security.lockdown;

  const stateTone = {
    NORMAL: "success",
    LOCKED: "warning",
    LOCKDOWN: "danger"
  }[data.systemState] || "neutral";

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
      light: {
        label: "Light",
        unit: " lux",
        value:
          data.history.at(-1)?.light
          ?? data.sensors.light
      },
      anomalyProbability: {
        label: "TinyML anomaly probability",
        unit: "%",
        value:
          (data.history.at(-1)?.anomalyProbability
          ?? tinyml.probability) * 100
      }
    }),
    [data.history, data.sensors, tinyml.probability]
  );

  const activeChart = chartMeta[selectedChart];

  function renderOverview() {
    return (
      <>
        <SectionHeader
          eyebrow="Component 01"
          title="Secure greenhouse edge overview"
          description="Live node health, protected access, anomaly detection and fail-safe actuator control."
          right={
            <div className="header-statuses">
              <StatusPill
                value={mode === "LIVE" ? "LIVE FIREBASE" : "DEMO STREAM"}
                kind={mode === "LIVE" ? "success" : "warning"}
              />
              <StatusPill value={data.systemState} kind={stateTone} />
            </div>
          }
        />

        <div className="evidence-banner">
          <div>
            <strong>Evidence status</strong>
            <p>{data.project.evidenceLevel}</p>
          </div>
          <StatusPill value={data.project.stage.toUpperCase()} kind="warning" />
        </div>

        <div className="metric-grid metric-grid--six">
          <MetricCard
            label="Temperature"
            value={formatNumber(data.sensors.temperature)}
            unit="°C"
            hint="DHT22"
            tone={data.sensors.temperature >= 32 ? "warning" : "default"}
          />

          <MetricCard
            label="Humidity"
            value={formatNumber(data.sensors.humidity)}
            unit="%"
            hint="DHT22"
          />

          <MetricCard
            label="Light"
            value={formatNumber(data.sensors.light)}
            unit="lux"
            hint="BH1750 · 0x23"
            tone={data.sensors.light < 4 ? "danger" : "default"}
          />

          <MetricCard
            label="Soil"
            value={formatNumber(data.sensors.soilPercent, 0)}
            unit="%"
            hint={`Raw ${data.sensors.soilRaw}`}
            tone={data.sensors.soilValid ? "default" : "danger"}
          />

          <MetricCard
            label="TinyML risk"
            value={formatPercent(tinyml.probability)}
            hint={`${tinyml.confirmations}/${tinyml.requiredConfirmations} confirmations`}
            tone={tinyml.prediction ? "danger" : "default"}
          />

          <MetricCard
            label="RFID timing risk"
            value={formatPercent(rfid.timingRiskProbability)}
            hint="Evidence-only support signal"
            tone={rfid.timingRiskFlag ? "warning" : "default"}
          />
        </div>

        <div className="content-grid content-grid--wide-left">
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
                <option value="light">Light</option>
                <option value="anomalyProbability">TinyML probability</option>
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
            title="Live system state"
            subtitle="Deterministic safety is primary"
          >
            <div className="stack">
              <DetailRow
                label="Node"
                value={data.nodeId}
                mono
              />
              <DetailRow
                label="Connection"
                value={data.connection.toUpperCase()}
                tone={data.connection === "online" ? "success" : "danger"}
              />
              <DetailRow
                label="System state"
                value={data.systemState}
                tone={stateTone}
              />
              <DetailRow
                label="Scenario"
                value={data.scenario}
                mono
              />
              <DetailRow
                label="Authenticated session"
                value={session.active ? `ACTIVE · #${session.id}` : "INACTIVE"}
                tone={session.active ? "success" : "neutral"}
              />
              <DetailRow
                label="Enclosure"
                value={data.security.enclosure}
                tone={data.security.tamper ? "danger" : "success"}
              />
              <DetailRow
                label="Last update"
                value={timeLabel(data.timestamp)}
              />
            </div>
          </Panel>
        </div>

        <div className="content-grid content-grid--three">
          <Panel
            title="RFID protected access"
            subtitle={`${rfid.protectedSector} · marker ${rfid.marker}`}
          >
            <div className="stack">
              <DetailRow label="UID" value={rfid.uid} mono />
              <DetailRow
                label="Final result"
                value={rfid.result}
                tone={rfid.result === "AUTHORIZED" ? "success" : "danger"}
              />
              <DetailRow
                label="Marker valid"
                value={rfid.markerValid ? "YES" : "NO"}
                tone={rfid.markerValid ? "success" : "danger"}
              />
              <DetailRow
                label="Sector auth"
                value={`${rfid.authLatencyUs} µs`}
              />
              <DetailRow
                label="Protected pipeline"
                value={`${rfid.pipelineLatencyUs} µs`}
              />
            </div>
          </Panel>

          <Panel
            title="TinyML protection"
            subtitle="Three-consecutive-anomaly confirmation gate"
          >
            <Gauge
              value={tinyml.probability}
              label={tinyml.prediction ? "ANOMALY" : "NORMAL"}
            />
            <div className="compact-grid">
              <DetailRow
                label="Confirmations"
                value={`${tinyml.confirmations}/${tinyml.requiredConfirmations}`}
              />
              <DetailRow
                label="Inference"
                value={`${tinyml.inferenceLatencyUs} µs`}
              />
              <DetailRow
                label="Hard lockdown"
                value={tinyml.hardLockdownEnabled ? "ENABLED" : "DISABLED"}
                tone="success"
              />
            </div>
          </Panel>

          <Panel
            title="Runtime keys"
            subtitle="Runtime memory only"
          >
            <div className="stack">
              <DetailRow
                label="NwkSKey"
                value={keys.nwkSKey.state}
                tone={keys.nwkSKey.state === "ACTIVE" ? "success" : "danger"}
              />
              <DetailRow
                label="RFID Key A"
                value={keys.rfidKeyA.state}
                tone={keys.rfidKeyA.state === "ACTIVE" ? "success" : "danger"}
              />
              <DetailRow
                label="Zeroize on tamper"
                value="YES"
                tone="success"
              />
              <DetailRow
                label="Zeroize on TinyML lockdown"
                value="YES"
                tone="success"
              />
              <DetailRow
                label="Last verification"
                value={keys.lastZeroization.verification}
                tone="success"
              />
            </div>
          </Panel>
        </div>
      </>
    );
  }

  function renderInsider() {
    const incident = insider.lastIncident;

    return (
      <>
        <SectionHeader
          eyebrow="Threat scenario"
          title="Authenticated insider misuse"
          description="Tracks whether malicious operational behaviour occurred during a successfully authenticated RFID credential session."
          right={
            <StatusPill
              value={insider.passed ? "TEST PASSED" : "NOT VALIDATED"}
              kind={insider.passed ? "success" : "warning"}
            />
          }
        />

        <div className="metric-grid metric-grid--four">
          <MetricCard
            label="Scenario ID"
            value={insider.scenarioId}
            hint={insider.scenarioName}
          />
          <MetricCard
            label="Session correlation"
            value={insider.authenticatedSessionCreated ? "YES" : "NO"}
            hint={insider.attributionScope}
            tone="success"
          />
          <MetricCard
            label="Pump safety"
            value={insider.pumpBlocked ? "BLOCKED" : "NOT BLOCKED"}
            hint="Open-circuit soil sensor cannot keep pump running"
            tone={insider.pumpBlocked ? "success" : "danger"}
          />
          <MetricCard
            label="Final response"
            value={incident.result}
            hint={`${incident.confirmations} confirmations`}
            tone="danger"
          />
        </div>

        <div className="content-grid content-grid--wide-right">
          <Panel
            title="Formal misuse sequence"
            subtitle="Validated sequence from authorized entry to hard lockdown"
          >
            <div className="attack-flow">
              {[
                ["1", "Authorized RFID", "Protected Sector 4 authentication succeeded"],
                ["2", "Session created", "Credential session #1 became active"],
                ["3", "Operational misuse", "Soil sensor disconnected / open-circuit"],
                ["4", "Deterministic block", "Pump command forced OFF"],
                ["5", "TinyML confirmation", "Anomaly reached 3/3 confirmations"],
                ["6", "Security response", "Keys zeroized and permanent lockdown entered"]
              ].map(([step, title, text]) => (
                <div className="attack-flow__item" key={step}>
                  <span>{step}</span>
                  <div>
                    <strong>{title}</strong>
                    <p>{text}</p>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel
            title="Last insider incident"
            subtitle="Forensic snapshot"
          >
            <div className="stack">
              <DetailRow label="Session ID" value={`#${incident.sessionId}`} />
              <DetailRow label="Trigger" value={incident.trigger} />
              <DetailRow
                label="Probability"
                value={formatPercent(incident.probability)}
                tone="danger"
              />
              <DetailRow label="Confirmations" value={incident.confirmations} />
              <DetailRow label="Response time" value={`${incident.responseMs} ms`} />
              <DetailRow
                label="Result"
                value={incident.result}
                tone="danger"
              />
            </div>
          </Panel>
        </div>

        <div className="content-grid content-grid--two">
          <Panel
            title="Attribution boundary"
            subtitle="What the system can and cannot claim"
          >
            <div className="callout callout--warning">
              <strong>Credential-session attribution</strong>
              <p>{session.attribution}</p>
            </div>

            <div className="stack">
              <DetailRow
                label="Authenticated credential present"
                value="YES"
                tone="success"
              />
              <DetailRow
                label="Misuse correlated to session"
                value="YES"
                tone="success"
              />
              <DetailRow
                label="Human identity proven"
                value={insider.humanIdentityClaimed ? "YES" : "NO"}
                tone={insider.humanIdentityClaimed ? "danger" : "warning"}
              />
            </div>
          </Panel>

          <Panel
            title="Insider-misuse controls"
            subtitle="Controls that prevent unsafe actuator operation"
          >
            <div className="stack">
              <DetailRow
                label="Open-circuit soil input"
                value="PUMP BLOCKED"
                tone="success"
              />
              <DetailRow
                label="Pump max runtime"
                value={`${data.actuators.pumpMaxRuntimeMs / 1000} seconds`}
              />
              <DetailRow
                label="Pump cooldown"
                value={`${data.actuators.pumpCooldownLimitMs / 1000} seconds`}
              />
              <DetailRow
                label="TinyML confirmation gate"
                value={`${tinyml.requiredConfirmations} consecutive anomalies`}
              />
              <DetailRow
                label="Recovery"
                value="PHYSICAL RESTART"
                tone="warning"
              />
            </div>
          </Panel>
        </div>
      </>
    );
  }

  function renderRfid() {
    const clone = rfid.cloneExperiment;
    const compare = rfid.timingComparison;

    return (
      <>
        <SectionHeader
          eyebrow="RFID security"
          title="Protected access and same-UID clone evidence"
          description="Separates deterministic credential verification from experimental timing-risk analysis."
          right={
            <StatusPill
              value={clone.universalCloneProof ? "CLONE-PROOF" : "NOT CLONE-PROOF"}
              kind={clone.universalCloneProof ? "success" : "warning"}
            />
          }
        />

        <div className="callout callout--warning">
          <strong>Research conclusion</strong>
          <p>{clone.conclusion}</p>
        </div>

        <div className="metric-grid metric-grid--five">
          <MetricCard
            label="Conclusive clone attempts"
            value={clone.conclusiveAttempts}
            hint="Same-UID research clone"
          />
          <MetricCard
            label="Clone authorized"
            value={clone.authorized}
            hint="Passed protected checks"
            tone="danger"
          />
          <MetricCard
            label="Clone rejected"
            value={clone.rejected}
            hint={`${clone.rejectionRate}% rejection rate`}
            tone="warning"
          />
          <MetricCard
            label="Selection failures"
            value={clone.cardSelectionFailures}
            hint="Inconclusive reader events"
          />
          <MetricCard
            label="Universal clone proof"
            value="NO"
            hint="Cannot be claimed"
            tone="warning"
          />
        </div>

        <div className="content-grid content-grid--two">
          <Panel
            title="Protected credential flow"
            subtitle="Deterministic RFID checks"
          >
            <div className="attack-flow">
              {[
                ["1", "UID selection", rfid.uid],
                ["2", "Sector authentication", `${rfid.protectedSector} using custom Key A`],
                ["3", "Protected marker read", rfid.marker],
                ["4", "Marker comparison", rfid.markerValid ? "VALID" : "INVALID"],
                ["5", "Final decision", rfid.result]
              ].map(([step, title, text]) => (
                <div className="attack-flow__item" key={step}>
                  <span>{step}</span>
                  <div>
                    <strong>{title}</strong>
                    <p>{text}</p>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel
            title="Current RFID timing support"
            subtitle={rfid.timingModelRole}
          >
            <Gauge
              value={rfid.timingRiskProbability}
              threshold={0.75}
              label={rfid.timingRiskFlag ? "ELEVATED" : "NOT ELEVATED"}
            />

            <div className="stack">
              <DetailRow
                label="Active action allowed"
                value={rfid.activeActionAllowed ? "YES" : "NO"}
                tone={rfid.activeActionAllowed ? "danger" : "success"}
              />
              <DetailRow
                label="Source data synthetic"
                value={rfid.sourceDataSynthetic ? "YES" : "NO"}
                tone={rfid.sourceDataSynthetic ? "warning" : "success"}
              />
              <DetailRow
                label="Deterministic RFID authority"
                value="PRIMARY"
                tone="success"
              />
            </div>
          </Panel>
        </div>

        <Panel
          title="Genuine vs clone timing comparison"
          subtitle={compare.evidence}
        >
          <div className="metric-grid metric-grid--six">
            <MetricCard label="Accuracy" value={formatPercent(compare.accuracy)} />
            <MetricCard label="Precision" value={formatPercent(compare.precision)} />
            <MetricCard label="Recall" value={formatPercent(compare.recall)} />
            <MetricCard label="F1" value={formatPercent(compare.f1)} />
            <MetricCard label="ROC-AUC" value={formatPercent(compare.rocAuc)} />
            <MetricCard
              label="False-positive rate"
              value={formatPercent(compare.falsePositiveRate)}
              tone="danger"
            />
          </div>

          <div className="callout callout--danger">
            <strong>Not safe for independent hard-lockdown decisions</strong>
            <p>
              The observed false-positive rate is too high. RFID timing remains
              evidence-only and cannot independently reject a card or lock the node.
            </p>
          </div>
        </Panel>
      </>
    );
  }

  function renderKeys() {
    const nwk = keys.nwkSKey;
    const rfidKey = keys.rfidKeyA;

    return (
      <>
        <SectionHeader
          eyebrow="Cryptographic runtime"
          title="NwkSKey, RFID Key A and zeroization"
          description="Shows what Component 1 currently protects locally and what remains for Component 2."
          right={
            <StatusPill value="SRAM RUNTIME PROTECTION" kind="success" />
          }
        />

        <div className="content-grid content-grid--two">
          <Panel
            title="Runtime NwkSKey"
            subtitle="Prototype local key container"
          >
            <div className="key-card">
              <div className="key-card__top">
                <div>
                  <span>Current state</span>
                  <strong>{nwk.state}</strong>
                </div>
                <StatusPill
                  value={nwk.state}
                  kind={nwk.state === "ACTIVE" ? "success" : "danger"}
                />
              </div>

              <div className="stack">
                <DetailRow label="Storage" value={nwk.storage} />
                <DetailRow label="Source" value={nwk.source} />
                <DetailRow label="Dashboard persistence" value={nwk.persistence} />
                <DetailRow
                  label="Zeroize on physical tamper"
                  value={nwk.zeroizeOnTamper ? "YES" : "NO"}
                  tone="success"
                />
                <DetailRow
                  label="Zeroize on TinyML lockdown"
                  value={nwk.zeroizeOnTinymlLockdown ? "YES" : "NO"}
                  tone="success"
                />
                <DetailRow
                  label="Verification"
                  value={nwk.verification}
                  tone="success"
                />
              </div>
            </div>
          </Panel>

          <Panel
            title="Runtime RFID Key A"
            subtitle={rfidKey.purpose}
          >
            <div className="key-card">
              <div className="key-card__top">
                <div>
                  <span>Current state</span>
                  <strong>{rfidKey.state}</strong>
                </div>
                <StatusPill
                  value={rfidKey.state}
                  kind={rfidKey.state === "ACTIVE" ? "success" : "danger"}
                />
              </div>

              <div className="stack">
                <DetailRow label="Storage" value={rfidKey.storage} />
                <DetailRow
                  label="Zeroize on physical tamper"
                  value={rfidKey.zeroizeOnTamper ? "YES" : "NO"}
                  tone="success"
                />
                <DetailRow
                  label="Zeroize on TinyML lockdown"
                  value={rfidKey.zeroizeOnTinymlLockdown ? "YES" : "NO"}
                  tone="success"
                />
                <DetailRow
                  label="Verification"
                  value={rfidKey.verification}
                  tone="success"
                />
              </div>
            </div>
          </Panel>
        </div>

        <div className="content-grid content-grid--wide-left">
          <Panel
            title="Key lifecycle"
            subtitle="Current Component 1 boundary"
          >
            <div className="lifecycle">
              {[
                ["Boot", "Runtime key material loaded into ESP32 memory"],
                ["Normal operation", "Keys remain active for local authentication and prototype security logic"],
                ["Physical tamper", "High-priority task forces relays OFF and clears runtime keys"],
                ["Confirmed TinyML anomaly", "Three confirmations trigger key zeroization and permanent lockdown"],
                ["Recovery", "Physical restart required"],
                ["Component 2", "Gateway-derived NwkSKey lifecycle will replace prototype source"]
              ].map(([title, text], index) => (
                <div className="lifecycle__item" key={title}>
                  <span>{index + 1}</span>
                  <div>
                    <strong>{title}</strong>
                    <p>{text}</p>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel
            title="Last zeroization evidence"
            subtitle={keys.lastZeroization.trigger}
          >
            <div className="stack">
              <DetailRow
                label="NwkSKey"
                value={keys.lastZeroization.nwkSKey}
                tone="success"
              />
              <DetailRow
                label="RFID Key A"
                value={keys.lastZeroization.rfidKeyA}
                tone="success"
              />
              <DetailRow
                label="Verification"
                value={keys.lastZeroization.verification}
                tone="success"
              />
              <DetailRow
                label="Recovery"
                value={keys.lastZeroization.recovery}
                tone="warning"
              />
            </div>
          </Panel>
        </div>

        <Panel
          title="Full NwkSKey lifecycle not yet complete"
          subtitle={nwk.fullLifecycleStatus}
        >
          <div className="missing-grid">
            {nwk.missingLifecycleItems.map((item) => (
              <div className="missing-item" key={item}>
                <span>Pending</span>
                <strong>{item}</strong>
              </div>
            ))}
          </div>
        </Panel>
      </>
    );
  }

  function renderTinyml() {
    return (
      <>
        <SectionHeader
          eyebrow="Edge intelligence"
          title="TinyML anomaly detection and hard lockdown"
          description="Five-feature Random Forest running directly on the ESP32."
          right={
            <StatusPill value="MODEL ACTIVE" kind="success" />
          }
        />

        <div className="metric-grid metric-grid--six">
          <MetricCard label="Trees" value={tinyml.trees} />
          <MetricCard label="Tree nodes" value={tinyml.nodes} />
          <MetricCard label="Features" value={tinyml.featureCount} />
          <MetricCard label="Test accuracy" value={formatPercent(tinyml.testAccuracy)} />
          <MetricCard label="Anomaly recall" value={formatPercent(tinyml.testRecall)} />
          <MetricCard label="False-positive rate" value={formatPercent(tinyml.testFalsePositiveRate)} />
        </div>

        <div className="content-grid content-grid--three">
          <Panel
            title="Live inference"
            subtitle={`${tinyml.model} · raw features`}
          >
            <Gauge
              value={tinyml.probability}
              label={tinyml.prediction ? "ANOMALY" : "NORMAL"}
            />
            <div className="stack">
              <DetailRow
                label="Confirmations"
                value={`${tinyml.confirmations}/${tinyml.requiredConfirmations}`}
              />
              <DetailRow
                label="Inference latency"
                value={`${tinyml.inferenceLatencyUs} µs`}
              />
              <DetailRow
                label="Source data synthetic"
                value={tinyml.sourceDataSynthetic ? "YES" : "NO"}
                tone="warning"
              />
            </div>
          </Panel>

          <Panel
            title="Model feature order"
            subtitle="Exact deployed input order"
          >
            <FeatureList items={tinyml.featureOrder} />
          </Panel>

          <Panel
            title="Hard-lockdown result"
            subtitle="Triggered only after confirmed anomaly"
          >
            <div className="stack">
              <DetailRow
                label="Confirmation requirement"
                value={`${tinyml.requiredConfirmations} consecutive predictions`}
              />
              <DetailRow label="Pump relay" value="HIGH / OFF" tone="success" />
              <DetailRow label="Fan relay" value="HIGH / OFF" tone="success" />
              <DetailRow label="NwkSKey" value="ZEROIZED" tone="success" />
              <DetailRow label="RFID Key A" value="ZEROIZED" tone="success" />
              <DetailRow label="RFID" value="DISABLED" tone="warning" />
              <DetailRow label="Sensor sampling" value="DISABLED" tone="warning" />
              <DetailRow label="Recovery" value="PHYSICAL RESTART" tone="warning" />
            </div>
          </Panel>
        </div>

        <Panel
          title="Safety hierarchy"
          subtitle="Which subsystem has authority"
        >
          <div className="authority-grid">
            {[
              ["1", "Physical tamper task", "Highest", "Immediate deterministic lockdown and zeroization"],
              ["2", "Deterministic actuator safety", "Primary", "Hysteresis, open-circuit blocking, max runtime and cooldown"],
              ["3", "Environmental TinyML", "Confirmed active response", "Requires 3/3 anomaly confirmations"],
              ["4", "RFID timing model", "Supporting only", "Evidence logging; no unlock, reject or lockdown authority"],
              ["5", "Dashboard", "Display only", "Read-only visualization and research evidence"]
            ].map(([number, title, level, text]) => (
              <div className="authority-item" key={number}>
                <span>{number}</span>
                <div>
                  <strong>{title}</strong>
                  <em>{level}</em>
                  <p>{text}</p>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </>
    );
  }

  function renderPlant() {
    return (
      <>
        <SectionHeader
          eyebrow="Operational safety"
          title="Sensors and actuators"
          description="Live sensor health, actuator commands and validated fail-safe thresholds."
        />

        <div className="metric-grid metric-grid--four">
          <MetricCard
            label="Soil raw"
            value={data.sensors.soilRaw}
            hint={data.sensors.soilValid ? "Valid connected sensor" : "Open circuit / implausible"}
            tone={data.sensors.soilValid ? "default" : "danger"}
          />
          <MetricCard
            label="Pump"
            value={data.actuators.pump ? "ON" : "OFF"}
            hint={data.actuators.pump ? "LOW / ON" : "HIGH / OFF"}
            tone={data.actuators.pump ? "warning" : "default"}
          />
          <MetricCard
            label="Fan"
            value={data.actuators.fan ? "ON" : "OFF"}
            hint={data.actuators.fan ? "LOW / ON" : "HIGH / OFF"}
            tone={data.actuators.fan ? "warning" : "default"}
          />
          <MetricCard
            label="Failed samples"
            value={data.sensors.failedSamples}
            hint={data.sensors.sampleValid ? "Current sample valid" : "Current sample invalid"}
            tone={data.sensors.sampleValid ? "default" : "danger"}
          />
        </div>

        <div className="content-grid content-grid--two">
          <Panel
            title="Pump deterministic safety"
            subtitle="Active-low relay control"
          >
            <div className="stack">
              <DetailRow label="Relay safe state" value={data.actuators.safeLevel} tone="success" />
              <DetailRow label="Pump ON threshold" value={`≤ ${data.actuators.pumpOnThreshold}%`} />
              <DetailRow label="Pump OFF threshold" value={`≥ ${data.actuators.pumpOffThreshold}%`} />
              <DetailRow label="Maximum runtime" value={`${data.actuators.pumpMaxRuntimeMs / 1000} seconds`} />
              <DetailRow label="Cooldown" value={`${data.actuators.pumpCooldownLimitMs / 1000} seconds`} />
              <DetailRow
                label="Open-circuit response"
                value="PUMP BLOCKED"
                tone="success"
              />
            </div>
          </Panel>

          <Panel
            title="Fan deterministic safety"
            subtitle="Temperature hysteresis"
          >
            <div className="stack">
              <DetailRow label="Relay safe state" value={data.actuators.safeLevel} tone="success" />
              <DetailRow label="Fan ON threshold" value={`≥ ${data.actuators.fanOnThreshold}°C`} />
              <DetailRow label="Fan OFF threshold" value={`≤ ${data.actuators.fanOffThreshold}°C`} />
              <DetailRow label="Current runtime" value={formatDuration(data.actuators.fanRuntimeMs)} />
              <DetailRow label="TinyML feature" value="Relay runtime" />
            </div>
          </Panel>
        </div>

        <Panel
          title="Sensor health matrix"
          subtitle="Current component status"
        >
          <div className="sensor-grid">
            {[
              ["DHT22", `${formatNumber(data.sensors.temperature)}°C · ${formatNumber(data.sensors.humidity)}%`, true],
              ["BH1750", `${formatNumber(data.sensors.light)} lux`, data.sensors.light >= 0],
              ["Soil sensor", `${data.sensors.soilRaw} raw · ${formatNumber(data.sensors.soilPercent, 0)}%`, data.sensors.soilValid],
              ["Tamper reed", data.security.enclosure, !data.security.tamper],
              ["RC522", rfid.result, rfid.result === "AUTHORIZED"]
            ].map(([name, value, healthy]) => (
              <div className="sensor-card" key={name}>
                <div>
                  <strong>{name}</strong>
                  <span>{value}</span>
                </div>
                <StatusPill
                  value={healthy ? "HEALTHY" : "FAULT"}
                  kind={healthy ? "success" : "danger"}
                />
              </div>
            ))}
          </div>
        </Panel>
      </>
    );
  }

  function renderEvidence() {
    return (
      <>
        <SectionHeader
          eyebrow="Research validation"
          title="Tests, evidence and limitations"
          description="A clear separation between validated hardware behaviour, model-pipeline validation and pending real-data evidence."
        />

        <TestTable rows={data.testCoverage} />

        <div className="content-grid content-grid--two">
          <Panel
            title="Completed prototype claims"
            subtitle="Supported by implemented tests"
          >
            <div className="check-list">
              {[
                "Physical tamper forces relays OFF and zeroizes runtime keys",
                "Protected RFID checks include UID, Sector 4 authentication and marker validation",
                "Authorized insider misuse is correlated to an RFID credential session",
                "Open-circuit soil input blocks the pump",
                "Environmental TinyML runs on ESP32 with parity validation",
                "Three confirmed anomalies trigger hard lockdown",
                "RFID timing probability is displayed only as supporting evidence"
              ].map((item) => (
                <div className="check-list__item" key={item}>
                  <span>✓</span>
                  <p>{item}</p>
                </div>
              ))}
            </div>
          </Panel>

          <Panel
            title="Claims still restricted"
            subtitle="Do not overstate these areas"
          >
            <div className="check-list check-list--warning">
              {[
                "The system is not universally clone-proof",
                "RFID timing metrics are not final measured performance",
                "Synthetic TinyML results are not final real-world accuracy",
                "NwkSKey gateway derivation, HMAC, rotation and revocation remain Component 2",
                "Credential-session correlation does not prove human identity"
              ].map((item) => (
                <div className="check-list__item" key={item}>
                  <span>!</span>
                  <p>{item}</p>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </>
    );
  }

  function renderEvents() {
    return (
      <>
        <SectionHeader
          eyebrow="Forensics"
          title="Events and security evidence"
          description="Chronological edge-node evidence suitable for research reporting and incident review."
        />

        <div className="content-grid content-grid--wide-left">
          <Panel
            title="Event timeline"
            subtitle="Latest security and operational events"
          >
            <Timeline items={data.events} />
          </Panel>

          <Panel
            title="Current forensic context"
            subtitle="Snapshot for the active session"
          >
            <div className="stack">
              <DetailRow label="Session ID" value={`#${session.id}`} />
              <DetailRow label="Session active" value={session.active ? "YES" : "NO"} tone="success" />
              <DetailRow label="Auth event" value={session.authEvent} />
              <DetailRow label="Session age" value={formatDuration(session.ageMs)} />
              <DetailRow label="RFID UID" value={rfid.uid} mono />
              <DetailRow label="Scenario" value={data.scenario} mono />
              <DetailRow label="System state" value={data.systemState} tone={stateTone} />
            </div>
          </Panel>
        </div>

        <Panel
          title="Recommended event records"
          subtitle="Fields to keep in Firebase logs"
        >
          <div className="missing-grid">
            {[
              "Timestamp",
              "Node ID",
              "System state",
              "Scenario ID",
              "Authenticated session ID",
              "RFID final result",
              "RFID timing risk",
              "TinyML probability",
              "TinyML confirmations",
              "Tamper state",
              "Relay states",
              "Zeroization result",
              "Recovery requirement"
            ].map((item) => (
              <div className="missing-item" key={item}>
                <span>Field</span>
                <strong>{item}</strong>
              </div>
            ))}
          </div>
        </Panel>
      </>
    );
  }

  const view = {
    overview: renderOverview,
    insider: renderInsider,
    rfid: renderRfid,
    keys: renderKeys,
    tinyml: renderTinyml,
    plant: renderPlant,
    evidence: renderEvidence,
    events: renderEvents
  }[activeView];

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand__mark">C1</div>
          <div>
            <span className="eyebrow">Secure Greenhouse</span>
            <strong>Component 01</strong>
          </div>
        </div>

        <nav className="nav">
          {NAV_ITEMS.map(([id, label, number]) => (
            <button
              type="button"
              className={`nav__item ${activeView === id ? "nav__item--active" : ""}`}
              key={id}
              onClick={() => setActiveView(id)}
            >
              <span>{number}</span>
              {label}
            </button>
          ))}
        </nav>

        <div className="sidebar__status">
          <span>Node</span>
          <strong>{data.nodeId}</strong>
          <StatusPill
            value={data.connection === "online" ? "ONLINE" : "OFFLINE"}
            kind={data.connection === "online" ? "success" : "danger"}
          />
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar">
          <div>
            <span className="eyebrow">{data.project.title}</span>
            <h1>Component 1 Security Dashboard</h1>
          </div>

          <div className="topbar__actions">
            <StatusPill
              value={mode === "LIVE" ? "LIVE DATA" : "DEMO MODE"}
              kind={mode === "LIVE" ? "success" : "warning"}
            />
            <StatusPill value={data.systemState} kind={stateTone} />
          </div>
        </header>

        <main className="dashboard">
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

          {view()}
        </main>

        <footer className="footer">
          <span>{data.project.component} · {data.nodeId}</span>
          <span>
            Read-only dashboard · Security authority remains inside the ESP32 firmware
          </span>
        </footer>
      </div>
    </div>
  );
}

export default App;
