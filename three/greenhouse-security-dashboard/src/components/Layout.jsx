import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  BrainCircuit,
  Beaker,
  Database,
  Fingerprint,
  Gauge,
  KeyRound,
  LogOut,
  RadioTower,
  Shield,
  Sprout
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const links = [
  { to: "/", label: "System Overview", icon: Gauge },
  { to: "/sensors", label: "Live Sensors", icon: Sprout },
  { to: "/component1", label: "Component 1 Security", icon: Fingerprint },
  { to: "/component3", label: "Component 3 AI Defense", icon: BrainCircuit },
  { to: "/pipeline", label: "Secure Pipeline", icon: RadioTower },
  { to: "/keys", label: "Key Lifecycle", icon: KeyRound },
  { to: "/behavioral", label: "Behavioral Anomaly", icon: Activity },
  { to: "/events", label: "Attack Events", icon: AlertTriangle },
  { to: "/demo", label: "Demonstration Lab", icon: Beaker },
  { to: "/evidence", label: "Evidence", icon: BarChart3 }
];

export default function Layout() {
  const { user, logout } = useAuth();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand__mark">
            <Shield size={24} />
          </div>
          <div>
            <strong>Greenhouse</strong>
            <span>Security Console</span>
          </div>
        </div>

        <nav className="sidebar__nav">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `sidebar__link ${isActive ? "active" : ""}`
              }
            >
              <Icon size={19} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="user-chip">
            <Database size={18} />
            <div>
              <strong>Dashboard User</strong>
              <span>{user?.email || "Authenticated"}</span>
            </div>
          </div>
          <button className="button ghost full" type="button" onClick={logout}>
            <LogOut size={18} />
            Sign out
          </button>
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
