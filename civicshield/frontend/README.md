# CivicShield Frontend

React + TypeScript + Vite + Tailwind + React Flow + Recharts.

## Run

```bash
cd civicshield/frontend
npm install
npm run dev      # http://localhost:5173 (proxies /api → http://localhost:8000)
```

Set `VITE_API_BASE` to point at the backend when not using the proxy. Auth token lives in `localStorage` key `cs_token`.

## Routes (11)

Overview, Infrastructure Map, Assets, Security Assessments, Findings and Risk, Remediation, RecoveryLab, Incidents, Threat Intelligence, Reports, Settings and Audit Log.
