import { Navigate, Route, Routes } from "react-router-dom";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import OverviewPage from "./pages/OverviewPage";
import LiveSensorsPage from "./pages/LiveSensorsPage";
import Component1Page from "./pages/Component1Page";
import Component3Page from "./pages/Component3Page";
import SecurePipelinePage from "./pages/SecurePipelinePage";
import KeyLifecyclePage from "./pages/KeyLifecyclePage";
import BehavioralPage from "./pages/BehavioralPage";
import AttackEventsPage from "./pages/AttackEventsPage";
import DemoLabPage from "./pages/DemoLabPage";
import EvidencePage from "./pages/EvidencePage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<OverviewPage />} />
        <Route path="/sensors" element={<LiveSensorsPage />} />
        <Route path="/component1" element={<Component1Page />} />
        <Route path="/component3" element={<Component3Page />} />
        <Route path="/pipeline" element={<SecurePipelinePage />} />
        <Route path="/keys" element={<KeyLifecyclePage />} />
        <Route path="/behavioral" element={<BehavioralPage />} />
        <Route path="/events" element={<AttackEventsPage />} />
        <Route path="/demo" element={<DemoLabPage />} />
        <Route path="/evidence" element={<EvidencePage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
