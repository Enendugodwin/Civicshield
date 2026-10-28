import { useEffect, useState } from 'react';
import { Download, RefreshCcw, ShieldCheck, UserCog } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page, download } from '../components/ui';

export default function Settings() {
  const [audit, setAudit] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [err, setErr] = useState('');
  const [note, setNote] = useState('');
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [resetting, setResetting] = useState(false);

  const load = () => {
    setLoading(true);
    Promise.all([
      api.get('/api/audit'),
      api.health().catch(() => null),
    ]).then(([a, h]) => {
      setAudit(a.items ?? a ?? []);
      setHealth(h);
    }).catch((e) => setErr(String(e?.message ?? e))).finally(() => setLoading(false));
  };
  useEffect(load, []);

  const reset = async () => {
    if (!window.confirm('Reset the demo database? This replaces assets, findings, incidents and runs with the seeded demo data.')) return;
    setErr(''); setNote(''); setResetting(true);
    try {
      await api.post('/api/demo/reset', {});
      setNote('Demo data reset. Reloading records…');
      load();
    } catch (e: any) {
      setErr(String(e?.message ?? e));
    } finally {
      setResetting(false);
    }
  };

  const actions = [...new Set(audit.map((a) => String(a.action)))].sort();
  const visible = filter === 'ALL' ? audit : audit.filter((a) => a.action === filter);
  const aiOn = !!health?.ai?.available;

  return (
    <Page
      title="Settings & Audit"
      crumb="CivicShield / Program / Settings"
      actions={<span className="text-[11px] text-slate-500">{audit.length} recorded events</span>}
    >
      {err && <Err msg={err} retry={load} />}
      {note && <p role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.07] px-3 py-2 text-[12px] text-emerald-200">{note}</p>}

      <div className="grid gap-3 lg:grid-cols-3">
        <div className="card">
          <div className="mb-1.5 flex items-center gap-2">
            <ShieldCheck size={15} className={aiOn ? 'text-emerald-300' : 'text-amber-300'} aria-hidden="true" />
            <h2 className="text-[13px]">AI assistance</h2>
            <span className="ml-auto"><Badge text={aiOn ? 'ready' : 'fallback'} /></span>
          </div>
          <p className="text-[11.5px] leading-relaxed text-slate-400">
            Mode <span className="font-mono text-slate-200">{health?.ai?.mode ?? 'unknown'}</span>.
            {aiOn
              ? ' A model is reachable for explanations and remediation plans.'
              : ' Deterministic offline guidance is used; nothing is sent to an external model.'}
          </p>
          <p className="mt-2 text-[10.5px] text-slate-500">Provider health is read from <span className="font-mono">GET /api/health</span>.</p>
        </div>

        <div className="card">
          <div className="mb-1.5 flex items-center gap-2">
            <UserCog size={15} className="text-slate-400" aria-hidden="true" />
            <h2 className="text-[13px]">Access model</h2>
          </div>
          <dl className="grid gap-1 text-[11.5px]">
            <div className="flex justify-between gap-2"><dt className="text-slate-500">Viewer</dt><dd className="text-slate-300">read-only</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-slate-500">Operator</dt><dd className="text-slate-300">assessments, workflow, recovery</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-slate-500">Admin</dt><dd className="text-slate-300">deletes and demo reset</dd></div>
          </dl>
          <p className="mt-2 text-[10.5px] text-slate-500">
            This demo signs in as <strong className="text-slate-300">Demo Owner (admin)</strong>, so all actions are available.
            Use the role selector in the sidebar to preview operator or viewer restrictions.
            The <span className="font-mono">X-Role</span> header is a demo control, not production authentication.
          </p>
        </div>

        <div className="card">
          <div className="mb-1.5 flex items-center gap-2">
            <RefreshCcw size={15} className="text-amber-300" aria-hidden="true" />
            <h2 className="text-[13px]">Demo data</h2>
          </div>
          <p className="text-[11.5px] leading-relaxed text-slate-400">
            Restore the seeded water-utility estate. This replaces current records, findings and runs.
          </p>
          <button className="btn-sec mt-2 border-rose-500/30 text-rose-200 hover:bg-rose-500/10" onClick={reset} disabled={resetting}>
            <RefreshCcw size={13} aria-hidden="true" /> {resetting ? 'Resetting…' : 'Reset demo environment'}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="mb-2 flex flex-wrap items-baseline gap-2">
          <h2 className="text-[13px]">Audit log</h2>
          <span className="font-mono text-[10px] text-slate-500">{visible.length} of {audit.length}</span>
          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <select aria-label="Filter audit events by action" className="input w-auto py-1 text-[11px]" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="ALL">All actions</option>
              {actions.map((a) => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
            </select>
            <button className="btn-sec" onClick={() => download('/api/audit', 'audit-log.json')}>
              <Download size={13} aria-hidden="true" /> JSON
            </button>
          </div>
        </div>
        {loading ? <Loading msg="Loading audit log" /> : audit.length === 0 ? <Empty msg="No audit events." /> : (
          <div className="tblwrap max-h-[55vh] overflow-y-auto">
            <table className="tbl min-w-[560px]">
              <thead><tr><th>ID</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead>
              <tbody>
                {visible.map((a: any, i: number) => (
                  <tr key={a.id ?? i}>
                    <td className="font-mono text-[10.5px] text-slate-500">{a.id ?? i}</td>
                    <td className="text-slate-200">{a.actor}</td>
                    <td><Badge text={String(a.action).replace(/_/g, ' ')} /></td>
                    <td className="max-w-[34rem] truncate text-slate-400" title={a.detail}>{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {visible.length === 0 && <p className="py-4 text-center text-[12px] text-slate-500">No events for this action.</p>}
          </div>
        )}
        <p className="mt-2 text-[10.5px] text-slate-500">
          Append-only security-relevant record of workflow changes, imports, scans and simulated recoveries.
        </p>
      </div>
    </Page>
  );
}
