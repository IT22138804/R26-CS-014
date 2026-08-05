import {
  Droplets,
  Fan,
  Lightbulb,
  Sprout,
  Thermometer,
  Waves
} from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import StatusBadge from "../components/StatusBadge";
import EmptyState from "../components/EmptyState";
import KeyValueGrid from "../components/KeyValueGrid";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { asArray, formatTimestamp, safeObject } from "../utils/data";

export default function LiveSensorsPage() {
  const base = `/greenhouse/${NODE_ID}`;
  const current = useFirebaseValue(`${base}/current`, {});
  const telemetry = useFirebaseValue(`${base}/telemetry/raw_stream`, {});

  const currentValue = safeObject(current.value);
  const sensors = safeObject(currentValue.sensors);
  const actuators = safeObject(currentValue.actuators);

  const history = asArray(telemetry.value)
    .map((row) => ({
      ...row,
      ...(row.sensors || {}),
      label: row.timestamp ? new Date(Number(row.timestamp) * 1000).toLocaleTimeString() : row.id
    }))
    .slice(-40);

  return (
    <>
      <PageHeader
        eyebrow="Real hardware telemetry"
        title="Live sensors and actuators"
        description="Validated DHT22, BH1750 and soil values with pump and fan safety state."
        action={<StatusBadge value={sensors.sampleValid ? "VALID" : "INVALID"} />}
      />

      <div className="metric-grid">
        <MetricCard title="Temperature" value={sensors.temperature ?? "—"} unit=" °C" icon={Thermometer} />
        <MetricCard title="Humidity" value={sensors.humidity ?? "—"} unit=" %" icon={Droplets} />
        <MetricCard title="Light" value={sensors.light ?? "—"} unit=" lux" icon={Lightbulb} />
        <MetricCard title="Soil moisture" value={sensors.soilPercent ?? "—"} unit=" %" icon={Sprout} />
        <MetricCard title="Pump" value={actuators.pump || "OFF"} icon={Waves} subtitle={`${actuators.pumpRuntimeMs || 0} ms runtime`} />
        <MetricCard title="Fan" value={actuators.fan || "OFF"} icon={Fan} subtitle={`${actuators.fanRuntimeMs || 0} ms runtime`} />
      </div>

      <SectionCard
        title="Telemetry history"
        subtitle="Records written under telemetry/raw_stream."
      >
        {history.length > 1 ? (
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={340}>
              <LineChart data={history}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="label" minTickGap={28} />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="temperature" name="Temperature °C" dot={false} />
                <Line type="monotone" dataKey="humidity" name="Humidity %" dot={false} />
                <Line type="monotone" dataKey="soilPercent" name="Soil %" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyState
            title="Historical telemetry not populated"
            message="The current value is available. The final integrated gateway will append raw_stream records for charts."
          />
        )}
      </SectionCard>

      <SectionCard title="Latest validated record">
        <KeyValueGrid
          items={[
            { label: "Node ID", value: currentValue.nodeId || NODE_ID },
            { label: "Session ID", value: currentValue.sessionId || "—" },
            { label: "Sequence", value: currentValue.sequence ?? "—" },
            { label: "Soil raw ADC", value: sensors.soilRaw ?? "—" },
            { label: "Sample valid", value: sensors.sampleValid ? "YES" : "NO", badge: true },
            { label: "Safety interlock", value: actuators.safetyInterlock || "UNKNOWN", badge: true },
            { label: "System state", value: currentValue.systemState || "UNKNOWN", badge: true },
            { label: "Timestamp", value: formatTimestamp(currentValue.timestamp) }
          ]}
        />
      </SectionCard>
    </>
  );
}
