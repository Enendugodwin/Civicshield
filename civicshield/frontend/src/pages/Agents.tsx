import { useEffect, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

export default function Agents() {
  const [agents, setAgents] = useState<any[]>([]);
  const [runs, setRuns] = useState<any[]>([]);
  const [kind, setKind] = useState('full_assessment');
  const [ref, setRef] = useState('');
  const [detail, setDetail] = useState<any>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [openAgent, setOpenAgent] = useState<string | null>(null);

  const load = () => {
    api.get('/api/agents').then((d: any) => setAgents(d.agents ?? [])).catch((e) => setErr(String(e)));
    api.get('/api/agents/investigations').then((d: any) => setRuns(d ?? [])).catch(() => {});
  };
  useEffect(load, []);

  const start = async () => {
    setErr(''); setBusy(true);
    try {
      const r = await api.post('/api/agents/investigations', { kind, ref });
      setDetail(r);
      setRuns((prev) => [{ id: r.id, kind: r.kind, ref: r.ref, status: r.status, created_at: Date.now() / 1000 }, ...prev]);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const inspect = async (id: number) => {
    try { setDetail(await api.get(`/api/agents/investigations/${id}`)); } catch (e: any) { setErr(String(e)); }
  };
  const cancel = async (id: number) => {
    try {
      setDetail(await api.post(`/api/agents/investigations/${id}/cancel`, {}));
      load();
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  return (
    <Page title="Agent Team" crumb="CivicShield / Security Workflow / Agents"
      actions={<span className="text-[10.5px] uppercase tracking-[0.07em] text-slate-500">
        {agents.length} agents · {runs.length} investigations
      </span>}>
      {err && <Err msg={err} />}

      <div className="card grid gap-2">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-500">New investigation (operator)</h3>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <label className="grid gap-1 text-[11px] text-slate-500">Request kind
            <select className="input sm:max-w-[240px]" value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Investigation kind">
              {['full_assessment', 'architecture_upload', 'critical_vulnerability', 'identity_activity', 'recovery_readiness', 'incident', 'threat_advisory', 'finding'].map((k) => (
                <option key={k} value={k}>{k}</option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-[11px] text-slate-500">Reference (optional finding / asset / incident id)
            <input className="input sm:max-w-[220px]" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="e.g. 53" aria-label="Reference id" />
          </label>
          <button className="btn" onClick={start} disabled={busy}>{busy ? 'Running team…' : 'Run investigation'}</button>
        </div>
        <p className="text-[11px] text-slate-500">
          Deterministic routing picks the specialists; each runs bounded rules-based analysis over live records.
          At most one shared-model call synthesizes the executive summary, with a template fallback offline.
        </p>
      </div>

      {detail && (
        <div className="card grid gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-slate-100">Run #{detail.id} · {detail.kind}{detail.ref ? ` · ref ${detail.ref}` : ''}</span>
            <Badge text={detail.status} />
            {detail.status === 'running' && (
              <button className="btn-sec ml-auto" onClick={() => cancel(detail.id)}>Cancel</button>
            )}
            {detail.summary?.executive && (
              <span className="ml-auto font-mono text-[10px] text-slate-500">model: {detail.summary.executive.model_used}</span>
            )}
          </div>
          {detail.summary?.executive?.text && (
            <p className="text-[12.5px] leading-relaxed text-slate-300">{detail.summary.executive.text}</p>
          )}
          <div className="grid gap-1">
            {detail.tasks.map((t: any) => (
              <div key={t.id}>
                <button
                  className="flex w-full flex-wrap items-center gap-2 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5 text-left text-[11.5px]"
                  onClick={() => setOpenAgent(openAgent === t.agent_id ? null : t.agent_id)}
                  aria-expanded={openAgent === t.agent_id}
                >
                  <span className="font-mono font-semibold text-slate-200">{t.agent_id}</span>
                  <span className="text-slate-500">batch {t.batch}</span>
                  <Badge text={t.status} />
                  <span className="font-mono text-[10px] text-slate-500">{t.attempts} attempt{t.attempts === 1 ? '' : 's'} · {t.elapsed_ms} ms</span>
                  {t.error && <span className="font-mono text-[10px] text-red-300">{t.error.slice(0, 120)}</span>}
                </button>
                {openAgent === t.agent_id && t.result && (
                  <div className="mt-1 rounded-md border border-line/60 bg-raised/20 px-2 py-1.5 text-[11.5px] text-slate-400">
                    <div>{t.result.summary}</div>
                    {(t.result.items ?? []).slice(0, 5).map((it: any, i: number) => (
                      <div key={i} className="mt-0.5 font-mono text-[10.5px] text-slate-500">
                        {it.asset ?? it.rule_id ?? it.incident_id ?? it.objective ?? it.area ?? it.family ?? JSON.stringify(it).slice(0, 90)}
                        {it.severity ? ` [${it.severity}]` : ''}{it.count ? ` ×${it.count}` : ''}
                      </div>
                    ))}
                    {(t.result.recommendations ?? []).slice(0, 3).map((r: any, i: number) => (
                      <div key={`r${i}`} className="mt-0.5 text-slate-300">→ {typeof r === 'string' ? r : r.proposal ?? r.objective ?? r.step ?? JSON.stringify(r).slice(0, 120)}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
          {(detail.summary?.conflicts ?? []).length > 0 && (
            <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-2.5 py-2 text-[11.5px] text-amber-200">
              <span className="section-label mr-1">Conflicts</span>
              {detail.summary.conflicts.map((c: any, i: number) => (
                <div key={i} className="mt-0.5">{c.type}: {c.note ?? c.asset ?? ''} {c.count ? `(×${c.count})` : ''}</div>
              ))}
            </div>
          )}
          {(detail.summary?.missing_evidence ?? []).length > 0 && (
            <div className="text-[11px] text-slate-500">Missing evidence: {detail.summary.missing_evidence.join(' · ')}</div>
          )}
        </div>
      )}

      <div className="card grid gap-2">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-500">Recent investigations</h3>
        {runs.length === 0 ? <Empty msg="No investigations yet." /> : (
          <div className="grid gap-1">
            {runs.slice(0, 15).map((r: any) => (
              <button key={r.id}
                className="flex flex-wrap items-center gap-2 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5 text-left text-[12px]"
                onClick={() => inspect(r.id)}>
                <span className="font-mono text-slate-200">#{r.id}</span>
                <span className="text-slate-300">{r.kind}{r.ref ? ` · ${r.ref}` : ''}</span>
                <Badge text={r.status} />
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="card grid gap-2">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-500">Registry — 13 agents, read-only tools</h3>
        {agents.length === 0 ? <Loading msg="Loading registry" /> : (
          <div className="grid gap-1.5 sm:grid-cols-2">
            {agents.map((a: any) => (
              <div key={a.id} className="rounded-md border border-line/60 bg-raised/30 px-2.5 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[12px] font-semibold text-slate-100">{a.id}</span>
                  {a.system && <Badge text="system" />}
                  <span className="font-mono text-[10px] text-slate-500">{a.mode} · ≤{a.budget?.max_seconds ?? '?'}s</span>
                </div>
                <div className="mt-0.5 text-[12px] text-slate-300">{a.name}</div>
                <div className="text-[11px] text-slate-500">{a.purpose}</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {(a.capabilities ?? []).slice(0, 4).map((c: string) => <Badge key={c} text={c} />)}
                </div>
                {(a.tools ?? []).length > 0 && (
                  <div className="mt-1 font-mono text-[10px] text-slate-500">tools: {a.tools.map((t: any) => t.tool).join(', ')}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </Page>
  );
}
