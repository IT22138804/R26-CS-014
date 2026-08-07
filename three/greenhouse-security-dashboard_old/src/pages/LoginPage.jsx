import { useState } from "react";
import { Navigate } from "react-router-dom";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const { user, authLoading, login } = useAuth();
  const [form, setForm] = useState({ email: "", password: "" });
  const [status, setStatus] = useState({ loading: false, error: "" });

  if (!authLoading && user) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setStatus({ loading: true, error: "" });

    try {
      await login(form.email.trim(), form.password);
    } catch (error) {
      setStatus({
        loading: false,
        error: error?.message || "Dashboard sign-in failed."
      });
    }
  }

  return (
    <div className="login-screen">
      <div className="login-visual">
        <div className="login-visual__content">
          <div className="hero-icon">
            <ShieldCheck size={38} />
          </div>
          <span className="page-header__eyebrow">Attack-resilient IoT greenhouse</span>
          <h1>See every security decision from sensor to Firebase.</h1>
          <p>
            Monitor RFID authentication, TinyML inference, encrypted E32 transport,
            replay protection, key rotation, revocation and behavioral anomalies.
          </p>
          <div className="login-feature-grid">
            <div><strong>AES-GCM</strong><span>Encrypted telemetry</span></div>
            <div><strong>HMAC-SHA256</strong><span>Packet integrity</span></div>
            <div><strong>±30 s</strong><span>Timestamp window</span></div>
            <div><strong>3/3</strong><span>Anomaly confirmation</span></div>
          </div>
        </div>
      </div>

      <div className="login-panel">
        <form className="login-card" onSubmit={handleSubmit}>
          <div className="login-card__icon">
            <LockKeyhole size={24} />
          </div>
          <h2>Dashboard sign in</h2>
          <p>Use the separate Firebase Dashboard User account.</p>

          <label>
            Email
            <input
              type="email"
              autoComplete="username"
              required
              value={form.email}
              onChange={(event) =>
                setForm((current) => ({ ...current, email: event.target.value }))
              }
              placeholder="dashboard@example.com"
            />
          </label>

          <label>
            Password
            <input
              type="password"
              autoComplete="current-password"
              required
              value={form.password}
              onChange={(event) =>
                setForm((current) => ({ ...current, password: event.target.value }))
              }
              placeholder="Dashboard password"
            />
          </label>

          {status.error ? <div className="form-error">{status.error}</div> : null}

          <button className="button primary full" disabled={status.loading}>
            {status.loading ? "Signing in…" : "Sign in securely"}
          </button>

          <small>
            Real hardware paths are read-only. Demonstrations write only under
            the isolated Firebase demo path.
          </small>
        </form>
      </div>
    </div>
  );
}
