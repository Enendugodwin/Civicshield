import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Wrench } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Page } from '../components/ui';

const OPEN = new Set(['open', 'acknowledged', 'investigating']);

export default function Remediation() {
  const [params] = useSearchParams();
  const [fid, setFid] = useState(params.get('finding') ?? '');
  const [plan, setPlan] = useState<any>(null);
  const [audit, setAudit] = useState<any[]>([]);
  const [evidence, setEvidence] = useState('');
  const [findings, setFindings] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([
      api.get('/api/findings').catch(() => []),
      api.get('/api/assets').catch(() => []),
    ]).then(([f, a]) => {
      const list = (f.items ?? f ?? []).filter((x: any) => OPEN.has(String(x.workflow ?? 'open')));
      setFindings(list);
      setAssets(a.items ?? a ?? []);
      setFid((cur) => cur || String(list[0]?.id ?? ''));
    }).finally(() => setLoading(false));
  }, []);

  const assetName = (id: any) => {
    const a = assets.find((x) => String(x.id) === String(id));
    return a ? a.name || a.hostname : `Asset ${id}`;
  };
  const selected = useMemo(() => findings.find((f) => String(f.id) === String(fid)), [findings, fid]);

  const propose = async () => {
    setErr(''); setPlan(null); setBusy(true);
    try {
      const f = await api.get(`/api/findings/${fid}`);
      const p = await api.post('/api/remediation/propose', {
        finding_id: String(f.id ?? fid), rule_id: f.rule_id ?? 'UNKNOWN',
        title: f.rule_id ?? '', severity: f.severity ?? 'unknown',
        asset_id: String(f.asset_id ?? ''), evidence: f.detail ? [f.detail] : [],
      });
      setPlan(p);
      setAudit([]);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const applyFix = async () => {
    if (!plan?.id) return;
    setErr(''); setBusy(true);
    try {
      const r = await api.post(`/api/remediation/${plan.id}/apply`, {});
      setPlan({ ...plan, payload: { ...plan.payload, applied_fix: r } });
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const reopen = async () => {
    if (!plan?.id) return;
    setErr(''); setBusy(true);
    try {
      const r = await api.post(`/api/remediation/${plan.id}/reopen`, { actor: 'operator' });
      setPlan(r);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const act = async (kind: 'approve' | 'simulate' | 'verify' | 'reject') => {
    if (!plan?.id) return;
    setErr(''); setBusy(true);
    try {
      const body = kind === 'verify' ? { checks_passed: true, actor: 'operator', evidence } : { actor: 'operator' };
      const r = await api.post(`/api/remediation/${plan.id}/${kind}`, body);
      setPlan(r);
      const a = await api.get(`/api/remediation/${plan.id}/audit`).catch(() => ({ events: [] }));
      setAudit(a.events ?? a ?? []);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  useEffect(() => { if (params.get('finding')) propose(); }, []);

  const payload = plan?.payload ?? {};
  return (
    <Page title="Remediation" crumb="CivicShield / Security Workflow / Remediation"
      actions={<span className="text-[11px] text-slate-500">Advisory / simulated only — never touches production</span>}>
      {err && <Err msg={err} />}
      <div className="card grid gap-2">
        <div className="flex flex-wrap items-end gap-2">
          <label className="grid min-w-0 flex-1 gap-1 text-[11px] text-slate-500">
            Finding to remediate
            <select className="input" value={fid} onChange={(e) => { setFid(e.target.value); setPlan(null); setAudit([]); }}
              disabled={loading || findings.length === 0}>
              {findings.length === 0 && <option value="">No open findings</option>}
              {findings.map((f) => (
                <option key={f.id} value={f.id}>
                  #{f.id} · {f.rule_id} · {f.priority ?? f.severity} · {assetName(f.asset_id)}
                </option>
              ))}
            </select>
          </label>
          <button className="btn" onClick={propose} disabled={!fid || busy}>
            <Wrench size={14} aria-hidden="true" /> {busy ? 'Working…' : 'Generate plan'}
          </button>
        </div>
        {selected ? (
          <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
            <Badge text={String(selected.priority ?? selected.severity ?? 'unknown')} />
            <span className="font-mono">{selected.rule_id}</span>
            <span>· {assetName(selected.asset_id)}</span>
            <span className="min-w-0 flex-1 truncate" title={selected.detail}>{selected.detail}</span>
          </div>
        ) : !loading && (
          <Empty msg="No open findings. Run an assessment to generate findings first." />
        )}
      </div>

      {!plan && !loading && findings.length > 0 && (
        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">How remediation works</h2>
            <span className="ml-auto text-[10px] text-slate-500">evidence → action → verification</span>
          </div>
          <ol className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            {[
              ['Generate', 'The planner reads the finding, asset and evidence and drafts a corrective action.'],
              ['Approve', 'A reviewer accepts or rejects the plan before anything is simulated.'],
              ['Simulate', 'A non-production fix is applied and logged; production is never touched.'],
              ['Verify', 'Re-run the assessment and record evidence before the finding can close.'],
            ].map(([title, body], i) => (
              <li key={title} className="rounded-md border border-line/70 bg-raised/30 px-2.5 py-2">
                <span className="font-mono text-[10px] text-accent-soft">0{i + 1}</span>
                <div className="text-[11.5px] font-medium text-slate-100">{title}</div>
                <p className="mt-0.5 text-[10.5px] leading-relaxed text-slate-500">{body}</p>
              </li>
            ))}
          </ol>
          <p className="mt-2 text-[10.5px] text-slate-500">
            Plans are advisory. The assistant never executes production changes and every step is written to the audit log.
          </p>
        </div>
      )}

      {plan && (
        <div className="card grid gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-slate-100">Plan {plan.id}</span>
            <Badge text={String(plan.status)} />
            {plan.simulated && <Badge text="simulated" />}
            <span className="text-[11px] text-slate-500 ml-auto">model: {payload.model_used ?? 'fallback'}</span>
          </div>
          <p className="text-[13px] text-slate-300">{payload.plain_language}</p>
          <div className="grid md:grid-cols-2 gap-2 text-[13px]">
            <div><h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Corrective action</h3><p className="text-slate-200">{payload.corrective_action}</p></div>
            <div><h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Consequences if unresolved</h3><p className="text-slate-200">{payload.consequences}</p></div>
            <div><h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Prerequisites</h3><ul className="list-disc ml-4 text-slate-300">{(payload.prerequisites ?? []).map((p: string, i: number) => <li key={i}>{p}</li>)}</ul></div>
            <div><h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Verification steps</h3><ol className="list-decimal ml-4 text-slate-300">{(payload.verification_steps ?? []).map((p: string, i: number) => <li key={i}>{p}</li>)}</ol></div>
            <div><h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Rollback</h3><p className="text-slate-200">{payload.rollback}</p></div>
            <div><h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Limitations</h3><p className="text-slate-400">{payload.limitations || '—'}</p></div>
          </div>
          <div className="flex gap-2 flex-wrap">
            <button className="btn" onClick={() => act('approve')} disabled={busy}>Approve</button>
            <button className="btn-sec" onClick={() => act('simulate')} disabled={busy}>Simulate</button>
            <button className="btn-sec" onClick={() => applyFix()} disabled={busy || !['approved', 'simulated'].includes(plan.status)}>Apply simulated fix</button>
            <button className="btn-sec" onClick={() => act('reject')} disabled={busy}>Reject</button>
            {plan.status === 'verified' && <button className="btn-sec" onClick={() => reopen()} disabled={busy}>Reopen for rework</button>}
          </div>
          {payload.applied_fix && (
            <div className="text-[12px] text-emerald-300">Simulated fix applied: {payload.applied_fix.note} (rule {payload.applied_fix.rule_id}, asset {payload.applied_fix.asset_id}). <Link className="underline" to="/assessments">Re-run the assessment</Link> to verify the finding flips to PASS, then record verification below.</div>
          )}
          <div className="flex flex-col sm:flex-row gap-2">
            <input className="input" placeholder="Verification evidence (required to verify)" value={evidence} onChange={(e) => setEvidence(e.target.value)} aria-label="Verification evidence" />
            <button className="btn-sec" onClick={() => act('verify')} disabled={busy || !evidence}>Record verification</button>
          </div>
          {audit.length > 0 && (
            <div className="text-[12px] text-slate-400">
              <h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Audit trail</h3>
              {audit.map((a: any, i: number) => <div key={i}>{a.action} · {a.actor} · {a.detail}</div>)}
            </div>
          )}
        </div>
      )}
    </Page>
  );
}
