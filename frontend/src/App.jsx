import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import ComingSoon, { UPCOMING } from "./pages/ComingSoon";
import Alerts from "./pages/Alerts";
import Audit from "./pages/Audit";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import LiveEvents from "./pages/LiveEvents";
import Models from "./pages/Models";
import Overview from "./pages/Overview";
import Response from "./pages/Response";
import Rules from "./pages/Rules";
import Simulator from "./pages/Simulator";
import Login from "./pages/Login";
import Users from "./pages/Users";
import { useUser } from "./lib/auth";

export default function App() {
  const user = useUser();
  if (!user) return <Login />;            // not signed in: nothing else is reachable
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/events" element={<LiveEvents />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/models" element={<Models />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/response" element={<Response />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/simulator" element={<Simulator />} />
        {user.role === "admin" && <Route path="/users" element={<Users />} />}
        {Object.keys(UPCOMING).map((path) => (
          <Route key={path} path={path} element={<ComingSoon path={path} />} />
        ))}
        <Route path="*" element={<Overview />} />
      </Routes>
    </Layout>
  );
}
