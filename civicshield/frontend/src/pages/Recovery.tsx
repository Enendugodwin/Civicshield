import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Download, Play, RotateCcw, ShieldAlert, XCircle } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page, download } from '../components/ui';

const CRITERIA_LABEL: Record<string, string> = {
  recovery_procedure: 'procedure',
  backup_dependency: 'backup dependency',
  rto_configured: 'RTO',
};

export default function Recovery() {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [run, setRun] = useState<any>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<string | null>(null);
  const [readiness, setReadiness] = useState<any>(null);
  const [recs, setRecs] = useState<any[] | null>(null);
  const [recLoading, setRecLoading] = useState(false);

  useEffect(() => {
    api.post('/api/recovery/scenarios', {}).then((d: any) => setScenarios(d.items ?? d ?? []))
      .catch((e) => setErr(String(e?.message ?? e))).finally(() => setLoading(false));
    api.get('/api/recovery/readiness').then(setReadiness).catch(() => {});
    api.get('/api/assets').then((d: any) => setAssets(d.items ?? d ?? [])).catch(() => {});
    api.get('/api/reports/recovery').then((d: any) => {
      const list = d.runs ?? [];
      if (list.length) setRun({ result: list[list.length - 1] });
    }).catch(() => {});
  }, []);

  const start = async (id: any) => {
    setErr(''); setRunning(String(id));
    try {
      setRun(null); setRecs(null);
      const r = await api.post('/api/recovery/runs', { scenario_id: id });
      setRun(await api.get(`/api/recovery/runs/${r.id ?? r.run_id}`));
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setRunning(null); }
  };

  const recommend = async () => {
    if (!run?.run_id || recLoading) return;
    setErr(''); setRecLoading(true);
    try {
      const d = await api.post(`/api/recovery/runs/${run.run_id}/recommendations`, {});
      setRecs(d.recommendations ?? []);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setRecLoading(false); }
  };

  const view = run?.result ?? run;
  const m = view?.metrics ?? {};
  const steps = view?.steps ?? [];
  const assetName = (id: string | number) => {
    const a = assets.find((x) => String(x.id) === String(id));
    return a ? a.name || a.hostname : `Asset ${id}`;
  };
  const services = readiness?.services ?? [];
  const ready = services.filter((s: any) => s.ready).length;
  const rtoRows = useMemo(() => Object.entries(m.rto_met ?? {}), [m]);
  const actionLabel = (s: any) => {
    const hit = String(s.action ?? '').match(/^Restore and verify (\d+)$/);
    return hit ? `Restore and verify ${assetName(hit[1])}` : s.action;
  };

  return (
    <Page
      title="RecoveryLab"
      crumb="CivicShield / Resilience / RecoveryLab"
      actions={<span className="text-[11px] text-slate-500">Simulated plans — no production systems touched</span>}
    >
      {err && <Err msg={err} />}

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <div className="kpi">
          <div className="kpi-label">Services ready</div>
          <div className="kpi-value" style={{ color: services.length && ready === services.length ? '#34D399' : '#FBBF24' }}>
            {services.length ? `${ready}/${services.length}` : '—'}
          </div>
          <div className="text-[10px] text-slate-500">documented procedure, backup link, RTO</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Scenarios available</div>
          <div className="kpi-value">{scenarios.length}</div>
          <div className="text-[10px] text-slate-500">dependency-aware failure simulations</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Last simulated recovery</div>
          <div className="kpi-value">{m.simulated_minutes != null ? `${m.simulated_minutes}m` : '—'}</div>
          <div className="text-[10px] text-slate-500">{m.steps_success != null ? `${m.steps_success} steps succeeded` : 'no run yet'}</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">RTO status</div>
          <div className="kpi-value" style={{ color: rtoRows.length && rtoRows.every(([, ok]) => ok) ? '#34D399' : rtoRows.length ? '#F87171' : '#94A3B8' }}>
            {rtoRows.length ? `${rtoRows.filter(([, ok]) => ok).length}/${rtoRows.length}` : '—'}
          </div>
          <div className="text-[10px] text-slate-500">affected services inside RTO</div>
        </div>
      </div>

      <div className="grid items-start gap-3 xl:grid-cols-[1fr_1.15fr]">
        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">Recovery readiness by service</h2>
            <span className="ml-auto font-mono text-[10px] text-slate-500">{ready}/{services.length} ready</span>
          </div>
          {readiness ? (
            <div className="grid gap-2">
              {services.map((s: any) => (
                <div key={s.service_id} className="rounded-md border border-line/70 bg-raised/30 px-2.5 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[12px] font-medium text-slate-100">{s.service}</span>
                    <Badge text={s.ready ? 'ready' : 'not ready'} />
                    <span className="ml-auto font-mono text-[10px] text-slate-500">RTO {s.rto_minutes ?? '—'}m</span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {Object.entries(s.criteria ?? {}).map(([k, ok]) => (
                      <span key={k} className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] ${
                        ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                      }`}>
                        {ok ? <CheckCircle2 size={10} aria-hidden="true" /> : <XCircle size={10} aria-hidden="true" />}
                        {CRITERIA_LABEL[k] ?? k}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
              {services.length === 0 && <span className="text-[12px] text-slate-500">No essential services recorded.</span>}
            </div>
          ) : <Loading msg="Loading recovery readiness" />}
          <p className="mt-2 text-[10.5px] text-slate-500">
            A service is never marked ready on a score alone; every criterion must be documented.
          </p>
        </div>

        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">Failure scenarios</h2>
            <span className="ml-auto text-[10px] text-slate-500">run against live asset graph</span>
          </div>
          {loading ? <Loading msg="Loading scenarios" /> : scenarios.length === 0 ? <Empty msg="No scenarios available." /> : (
            <div className="grid gap-2 sm:grid-cols-2">
              {scenarios.map((s: any) => (
                <div key={s.id} className="rounded-md border border-line/70 bg-raised/25 px-2.5 py-2">
                  <div className="text-[12px] font-medium leading-snug text-slate-100">{s.name ?? s.id}</div>
                  <div className="mt-1 text-[10.5px] text-slate-500">
                    Seed failure: {(s.failed_assets ?? []).map(assetName).join(', ') || '—'}
                  </div>
                  <button className="btn-sec mt-2 w-full justify-center" onClick={() => start(s.id)} disabled={running !== null}>
                    {running === String(s.id)
                      ? <><RotateCcw size={13} className="animate-spin" aria-hidden="true" /> Running…</>
                      : <><Play size={13} aria-hidden="true" /> Run scenario</>}
                  </button>
                </div>
              ))}
            </div>
          )}
          {steps.length > 0 && (
            <div className="mt-3 border-t border-line/70 pt-2">
              <div className="section-label mb-1.5">Restoration order</div>
              <ol className="flex flex-wrap items-center gap-1.5">
                {(view?.order ?? []).map((id: string, i: number) => (
                  <li key={id} className="flex items-center gap-1.5">
                    {i > 0 && <ArrowRight size={11} className="text-slate-600" aria-hidden="true" />}
                    <span className="rounded border border-line bg-ink/60 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{assetName(id)}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      </div>

      {run && (
        <div className="grid gap-3">
          <div className="card">
            <div className="mb-2 flex flex-wrap items-baseline gap-2">
              <h2 className="text-[13px]">{run?.run_id ? `Run #${run.run_id}` : 'Latest simulated run'} — {view?.scenario?.name ?? view?.scenario?.id}</h2>
              <Badge text={m.steps_failed ? 'not ready' : 'ready'} />
              <button className="btn-sec ml-auto" disabled={!run?.run_id || recLoading}
                title={run?.run_id ? 'Generate AI recommendations for assets taken down in this run' : 'Re-run the scenario to generate recommendations'}
                onClick={recommend}>
                <ShieldAlert size={13} aria-hidden="true" /> {recLoading ? 'Generating…' : 'Generate AI recommendations'}
              </button>
              <button className="btn-sec"
                onClick={() => download('/api/reports/recovery', 'recovery-report.json')}>
                <Download size={13} aria-hidden="true" /> Export report
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
              {[
                ['Affected assets', m.affected_assets],
                ['Affected services', m.affected_services],
                ['Dependencies', m.dependencies_required],
                ['Backups available', m.backups_available],
                ['Steps succeeded', m.steps_success],
                ['Simulated minutes', m.simulated_minutes],
              ].map(([k, v]: any) => (
                <div key={k} className="rounded-md border border-line/70 bg-raised/30 px-2 py-1.5">
                  <div className="text-[9.5px] uppercase tracking-[0.06em] text-slate-500">{k}</div>
                  <div className="mt-0.5 font-display text-[15px] font-semibold tnum text-slate-100">{v ?? '—'}</div>
                </div>
              ))}
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {(view?.affected_services ?? []).map((s: string) => (
                <span key={s} className="badge border-accent/30 bg-accent/10 text-accent-soft">{s}</span>
              ))}
            </div>
          </div>

          {recs && (
            <div className="card">
              <h2 className="mb-1 text-[13px]">AI recommendations for this run</h2>
              <p className="mb-2 text-[11px] text-slate-500">
                Generated from open findings on the affected assets. Each planned item is stored in the
                remediation queue — review it on the <Link to="/remediation" className="text-accent-soft hover:underline">Remediation</Link> page.
              </p>
              {recs.length === 0 && <p className="text-[12px] text-slate-400">No affected assets in this run.</p>}
              <div className="grid gap-2">
                {recs.map((r: any) => (
                  <div key={r.asset_id} className="rounded-md border border-line/70 bg-raised/30 px-2 py-1.5">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="text-[12px] font-medium text-slate-200">{r.asset_name ?? r.asset_id}</span>
                      <Badge text={r.status === 'planned' ? 'planned' : 'no findings'} />
                      {r.model_used && <span className="font-mono text-[10px] text-slate-500">model: {r.model_used}</span>}
                      {r.plan_id && (
                        <Link to="/remediation" className="ml-auto inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
                          Open plan {r.plan_id} <ArrowRight size={12} aria-hidden="true" />
                        </Link>
                      )}
                    </div>
                    {r.status === 'planned' ? (
                      <>
                        <p className="mt-1 text-[12px] text-slate-300">{r.plain_language}</p>
                        <p className="mt-0.5 text-[11.5px] text-slate-400">{r.corrective_action}</p>
                      </>
                    ) : (
                      <p className="mt-1 text-[12px] text-slate-400">{r.note}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {rtoRows.length > 0 && (
            <div className="card">
              <h2 className="mb-2 text-[13px]">Recovery time objective</h2>
              <div className="grid gap-1.5 sm:grid-cols-2">
                {rtoRows.map(([svc, ok]) => (
                  <div key={svc} className="flex items-center gap-2 rounded-md border border-line/70 bg-raised/30 px-2 py-1.5 text-[11.5px]">
                    {ok
                      ? <CheckCircle2 size={13} className="text-emerald-300" aria-hidden="true" />
                      : <XCircle size={13} className="text-rose-300" aria-hidden="true" />}
                    <span className="text-slate-200">{svc}</span>
                    <span className={`ml-auto text-[10px] uppercase tracking-[0.06em] ${ok ? 'text-emerald-300' : 'text-rose-300'}`}>
                      {ok ? 'within RTO' : 'RTO breached'}
                    </span>
                  </div>
                ))}
              </div>
              {m.blockers?.length > 0 && (
                <p className="mt-2 flex items-start gap-1.5 text-[11px] text-rose-300">
                  <ShieldAlert size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
                  Blockers: {m.blockers.join(', ')}
                </p>
              )}
            </div>
          )}

          <div className="card">
            <div className="mb-2 flex items-baseline gap-2">
              <h2 className="text-[13px]">Recovery checklist</h2>
              <span className="ml-auto font-mono text-[10px] text-slate-500">
                {m.steps_success ?? 0} ok · {m.steps_failed ?? 0} failed
              </span>
            </div>
            <div className="tblwrap">
              <table className="tbl min-w-[600px]">
                <thead><tr><th>Step</th><th>Asset</th><th>Action</th><th>Status</th><th>Est.</th><th>Note</th></tr></thead>
                <tbody>
                  {steps.map((s: any) => (
                    <tr key={s.id}>
                      <td className="font-mono text-[10.5px] text-slate-500">{s.id}</td>
                      <td className="text-slate-200">{assetName(s.asset)}</td>
                      <td className="text-slate-300">{actionLabel(s)}</td>
                      <td><Badge text={String(s.status)} /></td>
                      <td className="tnum text-slate-400">{s.est_minutes}m</td>
                      <td className="max-w-[22rem] truncate text-slate-400" title={s.note}>{s.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Link to="/map" className="inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
                Inspect dependencies on the map <ArrowRight size={12} aria-hidden="true" />
              </Link>
              <Link to="/incidents" className="inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
                Open an incident <ArrowRight size={12} aria-hidden="true" />
              </Link>
            </div>
          </div>
        </div>
      )}
    </Page>
  );
}
