import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ children }) {
  const { user, authLoading } = useAuth();

  if (authLoading) {
    return (
      <div className="screen-center">
        <div className="loader" />
        <p>Checking dashboard access…</p>
      </div>
    );
  }

  return user ? children : <Navigate to="/login" replace />;
}
