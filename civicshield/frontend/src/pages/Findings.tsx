import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bot, ChevronDown, Network, ScanSearch, Wrench } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

const PAGE = 25;

export default function Findings() {
  const [items, setItems] = useState<any[]>([]);
  const [sev, setSev] = useState('');
  const [status, setStatus] = useState('');
  const [workflow, setWorkflow] = useState('open');
  const [source, setSource] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<number | null>(null);
  const [risk, setRisk] = useState<any>(null);
  const [impact, setImpact] = useState<any>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [limit, setLimit] = useState(PAGE);
  const [wf, setWf] = useState({ workflow: 'acknowledged', assignee: '', reason: '' });
  const [notice, setNotice] = useState('');
  const [checking, setChecking] = useState(false);
  const runArchChecks = async () => {
    setErr(''); setChecking(true);
    try {
      const r = await api.post('/api/architecture/checks/raise', {});
      setNotice(`Architecture checks: ${r.hit_count} hit${r.hit_count === 1 ? '' : 's'} — +${r.created} new, ${r.reopened} reopened, ${r.resolved_stale} resolved.`);
      load();
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setChecking(false); }
  };
  const load = () => {
    api.get('/api/findings').then((d: any) => setItems(d.items ?? d ?? [])).catch((e) => setErr(String(e))).finally(() => setLoading(false));
  };
  useEffect(() => { load(); api.get('/api/assets').then((d: any) => setAssets(d.items ?? d ?? [])).catch(() => {}); }, []);
  const assetName = (id: any) => {
    const a = assets.find((x) => String(x.id) === String(id));
    return a ? a.name || a.hostname : `Asset ${id}`;
  };
  const sourceOf = (x: any) => x.source ?? (String(x.rule_id).startsWith('CVE-') ? 'vulnerability' : String(x.rule_id).startsWith('AR-') ? 'architecture' : 'configuration');
  const filtered = useMemo(() => items.filter((x) =>
    (!sev || (x.priority ?? x.severity ?? '').toLowerCase() === sev) &&
    (!status || (x.status ?? '').toLowerCase() === status) &&
    (!source || sourceOf(x) === source) &&
    (!workflow || (x.workflow ?? 'open') === workflow))
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0)), [items, sev, status, source, workflow]);
  useEffect(() => { setLimit(PAGE); setOpen(null); }, [sev, status, source, workflow]);

  const sel = 'input w-full sm:max-w-[170px]';
  const inspect = async (f: any) => {
    if (open === f.id) { setOpen(null); return; }
    setOpen(f.id); setRisk(null); setImpact(null);
    setWf({ workflow: f.workflow ?? 'open', assignee: f.assignee ?? '', reason: '' });
    try {
      const [r, i] = await Promise.all([
        api.get(`/api/risk/${f.id}`),
        api.get(`/api/impact?asset_id=${f.asset_id}`).catch(() => null),
      ]);
      setRisk(r); setImpact(i);
    } catch (e: any) { setErr(String(e)); }
  };
  const saveWorkflow = async (f: any) => {
    try {
      await api.patch(`/api/findings/${f.id}`, wf);
      setOpen(null); load();
    } catch (e: any) { setErr(String(e)); }
  };
  const shown = filtered.slice(0, limit);

  return (
    <Page title="Findings and Risk" crumb="CivicShield / Security Workflow / Findings"
      actions={<span className="flex items-center gap-2">
        <span className="text-[10.5px] uppercase tracking-[0.07em] text-slate-500">{filtered.length} of {items.length} findings</span>
        <button className="btn-sec" onClick={runArchChecks} disabled={checking} title="Evaluate AR-* structural checks and raise findings">
          <ScanSearch size={12} aria-hidden="true" /> {checking ? 'Checking…' : 'Run architecture checks'}
        </button>
      </span>}>
      {err && <Err msg={err} />}
      {notice && <div className="card border-emerald-500/40 text-[12px] text-emerald-200">{notice}</div>}
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        <select className={sel} value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Filter by priority">
          <option value="">All priorities</option><option value="critical">Critical</option><option value="high">High</option>
          <option value="moderate">Moderate</option><option value="low">Low</option><option value="informational">Informational</option>
        </select>
        <select className={sel} value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All statuses</option><option value="confirmed">Confirmed</option><option value="inferred">Inferred</option><option value="simulated">Simulated</option>
        </select>
        <select className={sel} value={workflow} onChange={(e) => setWorkflow(e.target.value)} aria-label="Filter by workflow">
          <option value="">All workflows (includes resolved)</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option>
          <option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option>
        </select>
        <select className={sel} value={source} onChange={(e) => setSource(e.target.value)} aria-label="Filter by detection source">
          <option value="">All sources</option><option value="configuration">Configuration checks</option><option value="vulnerability">Known CVEs</option><option value="architecture">Architecture graph</option>
        </select>
      </div>

      {loading ? <Loading msg="Loading findings" /> : filtered.length === 0 ? <Empty msg="No findings match." /> : (
        <>
          <div className="grid gap-2">
            {shown.map((f: any) => (
              <div key={f.id} className="card">
                <div className="flex flex-wrap items-start gap-2">
                  <button
                    className="flex min-w-0 flex-1 flex-wrap items-center gap-2 text-left"
                    onClick={() => inspect(f)}
                    aria-expanded={open === f.id}
                  >
                    <ChevronDown size={13} aria-hidden="true" className={`shrink-0 text-slate-500 transition-transform ${open === f.id ? 'rotate-180' : ''}`} />
                    <span className={`font-mono text-[11.5px] font-semibold ${sourceOf(f) === 'vulnerability' ? 'text-accent-soft' : 'text-slate-100'}`}>{f.rule_id}</span>
                    {sourceOf(f) === 'vulnerability' && <Badge text="CVE" />}
                    <Badge text={String(f.priority ?? f.severity ?? 'unknown')} />
                    <Badge text={String(f.workflow ?? 'open')} />
                    {f.assignee && <span className="text-[10.5px] text-slate-500">→ {f.assignee}</span>}
                    <span className="font-mono text-[10px] text-slate-500">score {f.score ?? '—'} · {assetName(f.asset_id)} · {f.status}</span>
                  </button>
                  {sourceOf(f) === 'vulnerability' && (
                    <a className="btn-sec ml-auto shrink-0" href={`https://nvd.nist.gov/vuln/detail/${f.rule_id}`}
                      target="_blank" rel="noreferrer">NVD advisory</a>
                  )}
                  <Link className="btn-sec shrink-0" title="Ask the assistant about this finding"
                    to={`/assistant?q=${encodeURIComponent(`Tell me about finding #${f.id}`)}`}>
                    <Bot size={12} aria-hidden="true" /> Ask AI
                  </Link>
                  {sourceOf(f) === 'architecture' && (
                    <Link className="btn-sec shrink-0" title="Open the dependency graph behind this finding" to="/map">
                      <Network size={12} aria-hidden="true" /> Map
                    </Link>
                  )}
                  <Link className={`btn-sec shrink-0 ${sourceOf(f) === 'vulnerability' || sourceOf(f) === 'architecture' ? '' : 'ml-auto'}`} to={`/remediation?finding=${f.id}`}>
                    <Wrench size={12} aria-hidden="true" /> Remediate
                  </Link>
                </div>
                <div className="mt-1.5 pl-5 text-[12px] leading-relaxed text-slate-400">{f.detail || 'No detail recorded.'}</div>
                {open === f.id && (
                  <div className="mt-2 grid gap-2 border-t border-line/70 pt-2">
                    <div className="text-[11px] text-slate-400">
                      <span className="section-label mr-1">Risk factors ({risk?.model ?? '…'})</span>
                      {risk ? Object.entries(risk.factors).map(([k, v]: any) => `${k} ${v}`).join(' · ') : 'loading…'}
                    </div>
                    <div className="rounded-md border border-line/70 bg-raised/30 px-2.5 py-2 text-[11px] text-slate-400">
                      <span className="section-label mr-1">Service impact</span>
                      {impact == null ? 'loading…' : impact.affected_service_count === 0 ? (
                        <span>No mapped essential-service dependency for this asset.</span>
                      ) : (
                        <span>
                          {impact.affected_service_count} service{impact.affected_service_count === 1 ? '' : 's'} affected:{' '}
                          {impact.affected_services.map((s: any) => s.service).join(', ')}
                          {impact.affected_services[0]?.path?.length > 1 && (
                            <span className="ml-1 font-mono text-[10px] text-slate-500">
                              path {impact.affected_services[0].path.join(' → ')}
                            </span>
                          )}
                        </span>
                      )}
                    </div>
                    <div className="grid gap-2 sm:grid-cols-4">
                      <select className="input" value={wf.workflow} onChange={(e) => setWf({ ...wf, workflow: e.target.value })} aria-label="Workflow state">
                        <option value="open">open</option><option value="acknowledged">acknowledged</option>
                        <option value="investigating">investigating</option><option value="resolved">resolved</option>
                        <option value="false_positive">false positive</option>
                      </select>
                      <input className="input" placeholder="Assignee" value={wf.assignee} onChange={(e) => setWf({ ...wf, assignee: e.target.value })} aria-label="Assignee" />
                      <input className="input sm:col-span-2" placeholder="Reason (required to resolve or dismiss)" value={wf.reason} onChange={(e) => setWf({ ...wf, reason: e.target.value })} aria-label="Reason" />
                    </div>
                    <div><button className="btn-sec" onClick={() => saveWorkflow(f)}>Save workflow state</button></div>
                  </div>
                )}
              </div>
            ))}
          </div>
          {limit < filtered.length && (
            <div className="flex items-center justify-center gap-3">
              <span className="font-mono text-[10.5px] text-slate-500">Showing {shown.length} of {filtered.length}</span>
              <button className="btn-sec" onClick={() => setLimit((n) => n + PAGE)}>Load {Math.min(PAGE, filtered.length - limit)} more</button>
            </div>
          )}
        </>
      )}
    </Page>
  );
}
