import React, { Suspense, lazy, useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './index.css';
import Layout from './components/Layout';
import { api } from './api';
import { applyTheme, getTheme } from './theme';

applyTheme(getTheme());

// Route-level splitting: dashboard pulls Leaflet/Recharts, InfraMap pulls
// ReactFlow — none of it belongs in the initial chunk (Optimization Pack §3).
const Dashboard = lazy(() => import('./dashboard/Dashboard'));
const Overview = lazy(() => import('./pages/Overview'));
const InfraMap = lazy(() => import('./pages/InfraMap'));
const Assets = lazy(() => import('./pages/Assets'));
const Assessments = lazy(() => import('./pages/Assessments'));
const Findings = lazy(() => import('./pages/Findings'));
const Remediation = lazy(() => import('./pages/Remediation'));
const AIAssistant = lazy(() => import('./pages/AIAssistant'));
const Recovery = lazy(() => import('./pages/Recovery'));
const Incidents = lazy(() => import('./pages/Incidents'));
const Threats = lazy(() => import('./pages/Threats'));
const Reports = lazy(() => import('./pages/Reports'));
const Settings = lazy(() => import('./pages/Settings'));

function App() {
  const [ai, setAi] = useState('checking…');
  useEffect(() => {
    api.health().then((h: any) => setAi(h?.ai?.available ? 'online' : 'fallback')).catch(() => setAi('unreachable'));
  }, []);
  return (
    <BrowserRouter><Suspense fallback={<div className="grid min-h-screen place-items-center bg-ink font-mono text-[12px] tracking-[0.08em] text-slate-500">LOADING CIVICSHIELD…</div>}>
    <Routes><Route element={<Layout aiStatus={ai} />}>
      <Route index element={<Overview />} /><Route path="overview" element={<Overview />} />
      <Route path="service-health" element={<Dashboard />} /><Route path="map" element={<InfraMap />} />
      <Route path="assets" element={<Assets />} /><Route path="assessments" element={<Assessments />} />
      <Route path="findings" element={<Findings />} /><Route path="remediation" element={<Remediation />} /><Route path="assistant" element={<AIAssistant />} />
      <Route path="recovery" element={<Recovery />} /><Route path="incidents" element={<Incidents />} />
      <Route path="threats" element={<Threats />} /><Route path="reports" element={<Reports />} />
      <Route path="settings" element={<Settings />} />
    </Route></Routes></Suspense></BrowserRouter>
  );
}
ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
