import { useEffect, useMemo, useState } from "react";
import {
  initialDashboardData,
  nextMockData
} from "./mockData";

const databaseUrl = (
  import.meta.env.VITE_FIREBASE_DATABASE_URL || ""
).replace(/\/$/, "");

const authToken = import.meta.env.VITE_FIREBASE_AUTH || "";
const nodeId = import.meta.env.VITE_NODE_ID || "GH_NODE_01";
const refreshInterval = Number(
  import.meta.env.VITE_REFRESH_INTERVAL_MS || 2500
);

function addAuth(url) {
  if (!authToken) {
    return url;
  }

  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}auth=${encodeURIComponent(authToken)}`;
}

function normalizeLiveData(current, logs) {
  const fallback = initialDashboardData;
  const rawEvents = logs && typeof logs === "object"
    ? Object.entries(logs)
        .map(([id, event]) => ({
          id,
          time:
            event.timestamp
            || event.timestamp_ms
            || Date.now(),
          type: event.type || event.event_name || "SYSTEM",
          severity: event.severity || "info",
          message:
            event.message
            || event.event_name
            || "Greenhouse event"
        }))
        .sort((a, b) => b.time - a.time)
        .slice(0, 25)
    : fallback.events;

  return {
    ...fallback,
    ...current,
    nodeId: current?.nodeId || current?.node_id || nodeId,
    timestamp:
      current?.timestamp
      || current?.timestamp_ms
      || Date.now(),
    connection: "online",
    systemState:
      current?.systemState
      || current?.system_state
      || fallback.systemState,
    scenario:
      current?.scenario
      || current?.scenario_name
      || fallback.scenario,
    sensors: {
      ...fallback.sensors,
      ...(current?.sensors || {}),
      temperature:
        current?.sensors?.temperature
        ?? current?.temperature
        ?? fallback.sensors.temperature,
      humidity:
        current?.sensors?.humidity
        ?? current?.humidity
        ?? fallback.sensors.humidity,
      light:
        current?.sensors?.light
        ?? current?.lux
        ?? fallback.sensors.light,
      soilRaw:
        current?.sensors?.soilRaw
        ?? current?.soil_raw
        ?? fallback.sensors.soilRaw,
      soilPercent:
        current?.sensors?.soilPercent
        ?? current?.soil_percent
        ?? fallback.sensors.soilPercent,
      soilValid:
        current?.sensors?.soilValid
        ?? current?.soil_valid
        ?? fallback.sensors.soilValid
    },
    actuators: {
      ...fallback.actuators,
      ...(current?.actuators || {})
    },
    security: {
      ...fallback.security,
      ...(current?.security || {}),
      rfid: {
        ...fallback.security.rfid,
        ...(current?.security?.rfid || current?.rfid || {})
      },
      tinyml: {
        ...fallback.security.tinyml,
        ...(current?.security?.tinyml || current?.tinyml || {})
      },
      session: {
        ...fallback.security.session,
        ...(current?.security?.session || current?.session || {})
      },
      keys: {
        ...fallback.security.keys,
        ...(current?.security?.keys || current?.keys || {})
      }
    },
    events: rawEvents,
    history:
      Array.isArray(current?.history)
        ? current.history
        : fallback.history
  };
}

export function useGreenhouseData() {
  const liveMode = Boolean(databaseUrl);
  const [data, setData] = useState(initialDashboardData);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(liveMode);

  useEffect(() => {
    if (!liveMode) {
      const timer = window.setInterval(() => {
        setData((previous) => nextMockData(previous));
      }, refreshInterval);

      return () => window.clearInterval(timer);
    }

    let cancelled = false;

    async function loadLiveData() {
      try {
        const currentUrl = addAuth(
          `${databaseUrl}/greenhouse/${nodeId}/current.json`
        );
        const logsUrl = addAuth(
          `${databaseUrl}/greenhouse/${nodeId}/logs.json`
        );

        const [currentResponse, logsResponse] = await Promise.all([
          fetch(currentUrl),
          fetch(logsUrl)
        ]);

        if (!currentResponse.ok) {
          throw new Error(
            `Current-data request failed: ${currentResponse.status}`
          );
        }

        const current = await currentResponse.json();
        const logs = logsResponse.ok
          ? await logsResponse.json()
          : null;

        if (!cancelled) {
          setData(normalizeLiveData(current || {}, logs));
          setError("");
          setLoading(false);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || "Unable to load live data");
          setLoading(false);
          setData((previous) => ({
            ...previous,
            connection: "offline"
          }));
        }
      }
    }

    loadLiveData();
    const timer = window.setInterval(loadLiveData, refreshInterval);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [liveMode]);

  return useMemo(
    () => ({
      data,
      error,
      loading,
      mode: liveMode ? "LIVE" : "DEMO"
    }),
    [data, error, loading, liveMode]
  );
}
