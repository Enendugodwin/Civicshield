import React from 'react';
import { AlertTriangle, Inbox } from 'lucide-react';

export const SEV_COLOR: Record<string, string> = {
  Critical: '#ef4444', High: '#f59e0b', Moderate: '#eab308', Medium: '#eab308',
  Low: '#22c55e', Informational: '#60a5fa',
};
export const STATUS_COLOR: Record<string, string> = {
  Down: '#ef4444', Degraded: '#f59e0b', 'At Risk': '#eab308',
  Recovering: '#3b82f6', Operational: '#22c55e', open: '#f59e0b', complete: '#22c55e',
  enabled: '#22c55e', active: '#22c55e', yes: '#22c55e', ready: '#22c55e',
  disabled: '#ef4444', no: '#ef4444', 'not ready': '#ef4444', expired: '#64748b', unknown: '#eab308',
  PASS: '#22c55e', FAIL: '#ef4444', NA: '#64748b',
};
const KIND_COLOR: Record<string, string> = {
  observed: '#60a5fa', evidence: '#a78bfa', interpretation: '#eab308',
  suggestion: '#34d399', decision: '#f59e0b',
};

/** Shared chart palette so every Recharts surface matches the design system. */
export const CHART = {
  accent: '#34D399',
  info: '#60A5FA',
  warn: '#F59E0B',
  danger: '#EF4444',
  grid: '#26344D',
  axis: '#94A3B8',
  surface: '#192134',
};

export function colorFor(v: string) {
  const kd = Object.keys(KIND_COLOR).find((x) => x.toLowerCase() === v?.toLowerCase());
  if (kd) return KIND_COLOR[kd];
  const k = Object.keys(SEV_COLOR).find((x) => x.toLowerCase() === v?.toLowerCase());
  if (k) return SEV_COLOR[k];
  const s = Object.keys(STATUS_COLOR).find((x) => x.toLowerCase() === v?.toLowerCase());
  return s ? STATUS_COLOR[s] : '#94a3b8';
}

export function Badge({ text }: { text: string }) {
  const c = colorFor(text);
  return <span className="badge" style={{ background: c + '1f', color: c, border: `1px solid ${c}4d` }}>{text}</span>;
}

export function Page({ title, crumb, actions, children }: {
  title: string; crumb: string; actions?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div className="grid min-w-0 content-start gap-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:gap-4">
        <div className="min-w-0">
          <div className="mb-1 font-mono text-[10.5px] tracking-[0.02em] text-slate-500">{crumb}</div>
          <h1 className="break-words text-balance">{title}</h1>
        </div>
        {actions != null && (
          <div className="flex flex-wrap items-center gap-2 sm:ml-auto sm:justify-end">{actions}</div>
        )}
      </div>
      {children}
    </div>
  );
}

export function Err({ msg, retry }: { msg: string; retry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/[0.07] p-3 text-[13px] text-red-200">
      <AlertTriangle size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-red-400" />
      <span className="min-w-0 break-words">Error: {msg}</span>
      {retry && <button className="btn-sec ml-auto shrink-0" onClick={retry}>Retry</button>}
    </div>
  );
}

export function Empty({ msg }: { msg: string }) {
  return (
    <div className="card flex items-center gap-2.5 text-[13px] text-slate-500">
      <Inbox size={16} aria-hidden="true" className="shrink-0 text-slate-600" />
      <span>{msg}</span>
    </div>
  );
}

export function Loading({ msg }: { msg: string }) {
  return (
    <div className="card grid gap-2.5" role="status" aria-label={msg}>
      <span className="sr-only">{msg}…</span>
      <div className="skeleton h-3.5 w-1/3" />
      <div className="skeleton h-3.5 w-full" />
      <div className="skeleton h-3.5 w-2/3" />
    </div>
  );
}

export async function download(path: string, filename: string) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
