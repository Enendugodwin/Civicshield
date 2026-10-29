import { useEffect, useState } from 'react';
import { Download, Palette, RefreshCcw, ShieldCheck, UserCog } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page, download } from '../components/ui';
import { THEMES, applyTheme, getTheme, type ThemeId } from '../theme';

export default function Settings() {
  const [audit, setAudit] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [err, setErr] = useState('');
  const [note, setNote] = useState('');
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [resetting, setResetting] = useState(false);
  const [prot, setProt] = useState<any>(null);
  const [protForm, setProtForm] = useState({ enabled: true, interval_seconds: 3600, keep_runs: 50, notify_retention_days: 30 });
  const [policies, setPolicies] = useState<any>(null);
  const [dual, setDual] = useState(false);
  const [verify, setVerify] = useState<any>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeId>(getTheme());
  const pickTheme = (next: ThemeId) => {
    setTheme(next);
    applyTheme(next);
    setNote(`Theme set to ${THEMES.find((t) => t.id === next)?.label}. Preference saved on this device.`);
  };

  const load = () => {
    setLoading(true);
    Promise.all([
      api.get('/api/audit'),
      api.health().catch(() => null),
      api.get('/api/protection/status').catch(() => null),
      api.get('/api/governance/policies').catch(() => null),
    ]).then(([a, h, p, g]) => {
      setAudit(a.items ?? a ?? []);
      setHealth(h);
      setProt(p);
      if (p) setProtForm({
        enabled: !!p.enabled,
        interval_seconds: Number(p.interval_seconds ?? 3600),
        keep_runs: Number(p.keep_runs ?? 50),
        notify_retention_days: 30,
      });
      setPolicies(g);
      if (g) setDual(!!g.require_distinct_approver);
    }).catch((e) => setErr(String(e?.message ?? e))).finally(() => setLoading(false));
  };
  useEffect(load, []);

  const saveProt = async () => {
    if (busy) return;
    setErr(''); setNote(''); setBusy('prot');
    try {
      const d = await api.patch('/api/protection/config', protForm);
      setProt(d);
      setNote('Protection schedule updated.');
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(null); }
  };
  const runNow = async () => {
    if (busy) return;
    setErr(''); setNote(''); setBusy('run');
    try {
      const d = await api.post('/api/protection/run', {});
      setNote(`Reassessment run #${d.run_id} complete: +${d.opened} opened, ~${d.reopened} changed, -${d.resolved} cleared.`);
      const p = await api.get('/api/protection/status').catch(() => null);
      if (p) setProt(p);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(null); }
  };
  const savePolicies = async () => {
    if (busy) return;
    setErr(''); setNote(''); setBusy('gov');
    try {
      const d = await api.patch('/api/governance/policies', { require_distinct_approver: dual });
      setPolicies(d);
      setNote('Governance policy updated (admin).');
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(null); }
  };
  const verifyChain = async () => {
    if (busy) return;
    setErr(''); setNote(''); setBusy('verify'); setVerify(null);
    try {
      const d = await api.get('/api/governance/audit-verify');
      setVerify(d);
      setNote(d.ok ? `Audit chain verified: ${d.checked} events, head ${String(d.head ?? '').slice(0, 12)}…` : `Audit chain BROKEN at event ${d.broken_at}: ${d.reason}`);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(null); }
  };

  const [demoEnv, setDemoEnv] = useState('a');
  const reset = async () => {
    if (!window.confirm('Reset the demo database? This replaces assets, findings, incidents and runs with the seeded demo data.')) return;
    setErr(''); setNote(''); setResetting(true);
    try {
      const d = await api.post('/api/demo/reset', { env: demoEnv });
      setNote(`Demo data reset to environment ${d.env ?? demoEnv}. Reloading records…`);
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

      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
        <div className="card">
          <div className="mb-1.5 flex items-center gap-2">
            <Palette size={15} className="text-slate-400" aria-hidden="true" />
            <h2 className="text-[13px]">Appearance</h2>
          </div>
          <div className="grid gap-1.5" role="group" aria-label="Interface theme">
            {THEMES.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => pickTheme(t.id)}
                aria-pressed={theme === t.id}
                className={`flex items-center gap-2 rounded-md border px-2.5 py-2 text-left transition-colors ${theme === t.id ? 'border-accent bg-accent/[0.08]' : 'border-line bg-white/[0.02] hover:border-slate-500'}`}
              >
                <span
                  aria-hidden="true"
                  className="h-5 w-5 shrink-0 rounded border border-line"
                  style={{
                    background: t.id === 'light'
                      ? 'linear-gradient(135deg, #ffffff 55%, #cbd5e1 55%)'
                      : t.id === 'contrast' ? '#000000' : 'linear-gradient(135deg, #192134 55%, #059669 55%)',
                  }}
                />
                <span>
                  <span className="block text-[12px] font-medium text-slate-200">{t.label}</span>
                  <span className="block text-[10.5px] text-slate-500">{t.blurb}</span>
                </span>
              </button>
            ))}
          </div>
        </div>
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
            Restore a reproducible fictional estate. This replaces current records, findings and runs.
          </p>
          <label className="mt-1.5 grid gap-1 text-[10.5px] text-slate-500">Environment
            <select className="input py-1" value={demoEnv} onChange={(e) => setDemoEnv(e.target.value)} aria-label="Demo environment">
              <option value="a">A · Community water utility</option>
              <option value="b">B · Cloud SaaS</option>
              <option value="c">C · Hybrid enterprise</option>
            </select>
          </label>
          <button className="btn-sec mt-2 border-rose-500/30 text-rose-200 hover:bg-rose-500/10" onClick={reset} disabled={resetting}>
            <RefreshCcw size={13} aria-hidden="true" /> {resetting ? 'Resetting…' : 'Reset demo environment'}
          </button>
        </div>

        <div className="card">
          <div className="mb-1.5 flex items-center gap-2">
            <ShieldCheck size={15} className="text-slate-400" aria-hidden="true" />
            <h2 className="text-[13px]">Continuous protection</h2>
            {prot && <span className="ml-auto"><Badge text={prot.enabled ? 'scheduled' : 'paused'} /></span>}
          </div>
          <label className="flex items-center gap-1.5 text-[11.5px] text-slate-300">
            <input type="checkbox" checked={protForm.enabled} onChange={(e) => setProtForm({ ...protForm, enabled: e.target.checked })} />
            Scheduled reassessment enabled
          </label>
          <div className="mt-1.5 grid grid-cols-3 gap-1.5">
            <label className="grid gap-1 text-[10.5px] text-slate-500">Interval (s)
              <input type="number" min={60} max={86400} className="input py-1" value={protForm.interval_seconds}
                onChange={(e) => setProtForm({ ...protForm, interval_seconds: Number(e.target.value) })} aria-label="Reassessment interval seconds" />
            </label>
            <label className="grid gap-1 text-[10.5px] text-slate-500">Keep runs
              <input type="number" min={5} max={500} className="input py-1" value={protForm.keep_runs}
                onChange={(e) => setProtForm({ ...protForm, keep_runs: Number(e.target.value) })} aria-label="Protection runs retained" />
            </label>
            <label className="grid gap-1 text-[10.5px] text-slate-500">Notice days
              <input type="number" min={1} max={365} className="input py-1" value={protForm.notify_retention_days}
                onChange={(e) => setProtForm({ ...protForm, notify_retention_days: Number(e.target.value) })} aria-label="Notification retention days" />
            </label>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <button className="btn-sec" onClick={saveProt} disabled={busy === 'prot'}>{busy === 'prot' ? 'Saving…' : 'Save schedule'}</button>
            <button className="btn-sec" onClick={runNow} disabled={busy === 'run'}>{busy === 'run' ? 'Running…' : 'Run reassessment now'}</button>
          </div>
          <p className="mt-1.5 text-[10.5px] text-slate-500">
            Estate edits queue an event reassessment automatically; the scheduler re-runs detection on the interval.
          </p>
        </div>

        <div className="card">
          <div className="mb-1.5 flex items-center gap-2">
            <UserCog size={15} className="text-slate-400" aria-hidden="true" />
            <h2 className="text-[13px]">Governance</h2>
          </div>
          <label className="flex items-center gap-1.5 text-[11.5px] text-slate-300">
            <input type="checkbox" checked={dual} onChange={(e) => setDual(e.target.checked)} />
            Dual control for detection drafts
          </label>
          <p className="mt-1 text-[10.5px] text-slate-500">
            When on, activating a draft needs an approver other than its author (admin setting, enforced server-side).
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <button className="btn-sec" onClick={savePolicies} disabled={busy === 'gov'}>{busy === 'gov' ? 'Saving…' : 'Save policy'}</button>
            <button className="btn-sec" onClick={verifyChain} disabled={busy === 'verify'}>{busy === 'verify' ? 'Verifying…' : 'Verify audit chain'}</button>
          </div>
          {verify && (
            <p className={`mt-1.5 text-[11px] ${verify.ok ? 'text-emerald-300' : 'text-rose-300'}`} role="status">
              {verify.ok
                ? `Chain intact: ${verify.checked} events verified.`
                : `Chain broken at event ${verify.broken_at}: ${verify.reason}`}
            </p>
          )}
          <p className="mt-1.5 text-[10.5px] text-slate-500">
            Every audit insert is hash-chained (SHA-256 over previous hash, timestamp, actor, action, detail).
            The log is append-only: no update or delete endpoint exists.
          </p>
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
