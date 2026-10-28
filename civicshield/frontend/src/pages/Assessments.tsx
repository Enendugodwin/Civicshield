import { useEffect, useMemo, useState } from 'react';
import { Activity, Download, FileCheck2, Play, ShieldAlert, Terminal, TriangleAlert } from 'lucide-react';
import { api } from '../api';
import { Badge, Err, Loading, Page, download } from '../components/ui';

const OUTCOMES = ['ALL', 'PASS', 'FAIL', 'UNKNOWN'] as const;
const SEVERITIES = ['ALL', 'critical', 'high', 'medium', 'low'] as const;
const SOURCES = ['ALL', 'configuration', 'vulnerability'] as const;
const AREA_LABEL: Record<string, string> = {
  ASSET: 'Asset hygiene', ID: 'Identity & access', ENDP: 'Endpoint protection',
  BKP: 'Backup & recovery', VULN: 'Known vulnerabilities',
};
const areaOf = (ruleId: string) =>
  String(ruleId).startsWith('CVE-') ? 'VULN' : (String(ruleId).split('-')[1] ?? 'OTHER');
const sourceOf = (r: any) =>
  r.source ?? (String(r.rule_id).startsWith('CVE-') ? 'vulnerability' : 'configuration');

function when(ts?: number) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export default function Assessments() {
  const [runs, setRuns] = useState<any[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [results, setResults] = useState<any[]>([]);
  const [prevCounts, setPrevCounts] = useState<Record<string, number> | null>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingResults, setLoadingResults] = useState(false);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState('');
  const [outcome, setOutcome] = useState<string>('ALL');
  const [severity, setSeverity] = useState<string>('ALL');
  const [area, setArea] = useState<string>('ALL');
  const [source, setSource] = useState<string>('ALL');
  const [q, setQ] = useState('');
  const [posture, setPosture] = useState<any>(null);
  const [online, setOnline] = useState(false);
  const [summary, setSummary] = useState<any>(null);

  const loadRuns = async (pick?: number) => {
    const d: any = await api.get('/api/assessments');
    const list = d.items ?? d ?? [];
    setRuns(list);
    setSelected((cur) => pick ?? cur ?? (list.length ? list[list.length - 1].id : null));
  };

  useEffect(() => {
    Promise.all([
      loadRuns(),
      api.get('/api/assets').then((d: any) => setAssets(d.items ?? d ?? [])).catch(() => []),
      api.get('/api/detection/posture').then(setPosture).catch(() => null),
    ]).catch((e) => setErr(String(e?.message ?? e))).finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selected == null) return;
    let live = true;
    setLoadingResults(true);
    setErr('');
    const idx = runs.findIndex((r) => r.id === selected);
    const prev = idx > 0 ? runs[idx - 1] : null;
    Promise.all([
      api.get(`/api/assessments/${selected}`),
      prev ? api.get(`/api/assessments/${prev.id}`) : Promise.resolve([]),
    ]).then(([cur, old]) => {
      if (!live) return;
      setResults(cur.items ?? cur ?? []);
      const o: any[] = old.items ?? old ?? [];
      const counts: Record<string, number> = {};
      o.forEach((r) => { counts[String(r.outcome)] = (counts[String(r.outcome)] ?? 0) + 1; });
      setPrevCounts(prev ? counts : null);
    }).catch((e) => { if (live) setErr(String(e?.message ?? e)); })
      .finally(() => { if (live) setLoadingResults(false); });
    return () => { live = false; };
  }, [selected, runs]);

  useEffect(() => {
    setOutcome('ALL'); setSeverity('ALL'); setArea('ALL'); setSource('ALL'); setQ('');
  }, [selected]);

  const run = async () => {
    setErr(''); setRunning(true); setSummary(null);
    try {
      const result: any = await api.post('/api/detect', { online });
      setSummary(result);
      const d: any = await api.get('/api/assessments');
      const list = d.items ?? d ?? [];
      setRuns(list);
      const newest = list[list.length - 1];
      if (newest) setSelected(newest.id);
      api.get('/api/detection/posture').then(setPosture).catch(() => null);
      if (!result?.run_id) setErr('Detection completed but no run was recorded.');
    } catch (e: any) {
      setErr(String(e?.message ?? e));
    } finally {
      setRunning(false);
    }
  };

  const assetName = (id: string | number) => {
    const a = assets.find((x) => String(x.id) === String(id));
    return a ? a.name || a.hostname : `Asset ${id}`;
  };

  const counts = useMemo(() => {
    const c: Record<string, number> = { PASS: 0, FAIL: 0, UNKNOWN: 0 };
    results.forEach((r) => { c[String(r.outcome)] = (c[String(r.outcome)] ?? 0) + 1; });
    return c;
  }, [results]);

  const areas = useMemo(() => [...new Set(results.map((r) => areaOf(r.rule_id)))].sort(), [results]);
  const cveRows = useMemo(() => results.filter((r) => sourceOf(r) === 'vulnerability'), [results]);
  const cveCritical = cveRows.filter((r) => r.outcome === 'FAIL' && String(r.severity) === 'critical').length;
  const configFailed = results.filter((r) => r.outcome === 'FAIL' && sourceOf(r) === 'configuration').length;

  const filtered = useMemo(() => results.filter((r) => {
    if (outcome !== 'ALL' && r.outcome !== outcome) return false;
    if (severity !== 'ALL' && String(r.severity) !== severity) return false;
    if (area !== 'ALL' && areaOf(r.rule_id) !== area) return false;
    if (source !== 'ALL' && sourceOf(r) !== source) return false;
    if (q) {
      const hay = `${r.rule_id} ${r.asset_id} ${assetName(r.asset_id)} ${r.evidence_ref}`.toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  }), [results, outcome, severity, area, source, q, assets]);

  const failuresByArea = useMemo(() => {
    const m: Record<string, number> = {};
    results.filter((r) => r.outcome === 'FAIL').forEach((r) => {
      const k = areaOf(r.rule_id);
      m[k] = (m[k] ?? 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [results]);

  const current = runs.find((r) => r.id === selected);
  const coverage = results.length ? new Set(results.map((r) => String(r.asset_id))).size : 0;
  const delta = (key: string) => (prevCounts ? counts[key] - (prevCounts[key] ?? 0) : null);

  return (
    <Page
      title="Security Assessments"
      crumb="CivicShield / Security Workflow / Assessments"
      actions={
        <button className="btn" onClick={run} disabled={running}>
          <Play size={14} aria-hidden="true" />
          {running ? 'Detecting…' : 'Run detection'}
        </button>
      }
    >
      {err && <Err msg={err} retry={loadRuns} />}

      {loading ? <Loading msg="Loading assessment history" /> : (
        <>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-5">
            <div className="kpi">
              <div className="kpi-label">Selected run</div>
              <div className="kpi-value">{current ? `#${current.id}` : '—'}</div>
              <div className="text-[10px] text-slate-500">{current ? when(current.started_at) : 'no runs'}</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Failed controls</div>
              <div className="kpi-value" style={{ color: configFailed ? '#F87171' : '#34D399' }}>{configFailed}</div>
              <div className="text-[10px] text-slate-500">
                {counts.FAIL} total incl. CVEs · {delta('FAIL') == null ? 'no prior run' : `${delta('FAIL')! >= 0 ? '+' : ''}${delta('FAIL')} vs previous`}
              </div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Known vulnerabilities</div>
              <div className="kpi-value" style={{ color: cveRows.length ? '#F87171' : '#34D399' }}>{cveRows.length}</div>
              <div className="text-[10px] text-slate-500">{cveCritical} critical · version evidence</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Missing evidence</div>
              <div className="kpi-value" style={{ color: counts.UNKNOWN ? '#FBBF24' : '#34D399' }}>{counts.UNKNOWN}</div>
              <div className="text-[10px] text-slate-500">controls reported as unknown</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Asset coverage</div>
              <div className="kpi-value">{coverage}<span className="text-[13px] font-normal text-slate-500">/{assets.length}</span></div>
              <div className="text-[10px] text-slate-500">assets with recorded results</div>
            </div>
          </div>

          <div className="card">
            <div className="mb-2 flex flex-wrap items-baseline gap-2">
              <ShieldAlert size={14} className="text-accent-soft" aria-hidden="true" />
              <h2 className="text-[13px]">Detection coverage</h2>
              <span className="ml-auto font-mono text-[10px] text-slate-500">
                advisory snapshot {posture?.advisories?.snapshot ?? '…'}
              </span>
            </div>
            <div className="grid gap-2 sm:grid-cols-3">
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Current evidence</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">
                  {posture ? `${posture.assets_current}/${posture.assets_total}` : '—'}
                </div>
                <div className="text-[10px] text-slate-500">
                  {posture ? `${posture.assets_stale} stale · ${posture.assets_never} never collected` : 'loading'}
                </div>
              </div>
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Advisory set</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">
                  {posture?.advisories?.count ?? '—'}
                </div>
                <div className="text-[10px] text-slate-500">bundled CVEs · OSV optional</div>
              </div>
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Last detection</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">
                  {posture?.last_run ? `#${posture.last_run.id}` : '—'}
                </div>
                <div className="text-[10px] text-slate-500">
                  {posture?.last_run ? `${when(posture.last_run.started_at)} · ${posture.last_run.scope}` : 'no run yet'}
                </div>
              </div>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-1.5 text-[11px] text-slate-400">
                <input type="checkbox" checked={online} onChange={(e) => setOnline(e.target.checked)} />
                Enrich with OSV.dev (online, optional)
              </label>
              <span className="text-[10px] text-slate-500">
                Offline matching always runs. Online lookup only covers declared language packages.
              </span>
            </div>
            {summary && (
              <div className="mt-2 rounded-md border border-accent/25 bg-accent/[0.06] px-2.5 py-2 text-[11.5px] text-slate-300">
                Run #{summary.run_id}: {summary.assets} assets · {summary.outcomes?.FAIL ?? 0} failed controls ·{' '}
                <strong className="text-rose-300">{summary.vulnerabilities ?? 0} vulnerability matches</strong>{' '}
                ({summary.critical_vulnerabilities ?? 0} critical).
                {summary.warnings?.length > 0 && <span className="text-amber-300"> {summary.warnings.join(' ')}</span>}
              </div>
            )}
            <details className="mt-2">
              <summary className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-slate-400">
                <Terminal size={12} aria-hidden="true" /> Collect evidence from an authorized host
              </summary>
              <pre className="mt-1.5 overflow-x-auto rounded-md border border-line/70 bg-black/30 p-2 font-mono text-[10.5px] text-slate-300">{`python backend/agent/civicshield_agent.py collect \\
  --asset-id <asset-id> --push --run-detection \\
  --api http://127.0.0.1:8000 --token operator`}</pre>
              <p className="mt-1 text-[10.5px] text-slate-500">
                Read-only collector: no network scanning or host changes. It fills the same evidence schema these rules consume.
              </p>
            </details>
          </div>

          <div className="grid gap-3 xl:grid-cols-[15rem_1fr]">
            <div className="card self-start">
              <div className="mb-2 flex items-baseline gap-2">
                <h2 className="text-[13px]">Run history</h2>
                <span className="ml-auto font-mono text-[10px] text-slate-500">{runs.length}</span>
              </div>
              <ul className="grid gap-1">
                {[...runs].reverse().map((r) => {
                  const active = r.id === selected;
                  return (
                    <li key={r.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(r.id)}
                        aria-pressed={active}
                        className={`w-full rounded-md border px-2 py-1.5 text-left transition-colors ${
                          active ? 'border-accent/40 bg-accent/10' : 'border-transparent hover:border-line hover:bg-white/[0.035]'
                        }`}
                      >
                        <span className="flex items-center gap-1.5">
                          <Activity size={12} aria-hidden="true" className={active ? 'text-accent-soft' : 'text-slate-500'} />
                          <span className={`font-mono text-[11px] ${active ? 'text-slate-100' : 'text-slate-300'}`}>Run #{r.id}</span>
                          <span className="ml-auto"><Badge text={String(r.status ?? 'unknown')} /></span>
                        </span>
                        <span className="mt-0.5 block truncate text-[10px] text-slate-500">
                          {when(r.started_at)} · rules {r.rule_version}
                          {r.scope && r.scope !== 'all' ? ` · ${r.scope}` : ''}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              {runs.length === 0 && <p className="text-[11px] text-slate-500">No runs yet. Run the first assessment.</p>}
            </div>

            <div className="grid min-w-0 content-start gap-3">
              <div className="card">
                <div className="mb-2 flex flex-wrap items-baseline gap-2">
                  <h2 className="text-[13px]">Human-readable report</h2>
                  {current && <Badge text={String(current.status)} />}
                  <span className="ml-auto flex gap-1.5">
                    <button className="btn-sec" disabled={!selected}
                      onClick={() => download(`/api/assessments/${selected}/export?format=json`, `assessment-${selected}.json`)}>
                      <Download size={13} aria-hidden="true" /> JSON
                    </button>
                    <button className="btn-sec" disabled={!selected}
                      onClick={() => download(`/api/assessments/${selected}/export?format=csv`, `assessment-${selected}.csv`)}>
                      <Download size={13} aria-hidden="true" /> CSV
                    </button>
                  </span>
                </div>
                {selected == null ? (
                  <p className="text-[12px] text-slate-500">Select a run to inspect its results.</p>
                ) : (
                  <div className="grid gap-2.5">
                    <p className="text-[12.5px] leading-relaxed text-slate-300">
                      Run <span className="font-mono">#{selected}</span> assessed <strong className="text-slate-100">{coverage}</strong> assets
                      against rule version <span className="font-mono">{current?.rule_version ?? '—'}</span>.{' '}
                      <strong className="text-emerald-300">{counts.PASS}</strong> controls passed,{' '}
                      <strong className="text-rose-300">{configFailed}</strong> controls failed,{' '}
                      <strong className="text-amber-300">{counts.UNKNOWN}</strong> could not be decided, and{' '}
                      <strong className="text-rose-300">{cveRows.length}</strong> known-vulnerability matches were recorded.
                    </p>
                    <div className="flex h-2 overflow-hidden rounded-full bg-white/[0.06]" role="img"
                      aria-label={`${counts.PASS} pass, ${counts.FAIL} fail, ${counts.UNKNOWN} unknown`}>
                      {(['PASS', 'FAIL', 'UNKNOWN'] as const).map((k) => counts[k] > 0 && (
                        <span key={k} style={{
                          width: `${(counts[k] / Math.max(1, results.length)) * 100}%`,
                          background: k === 'PASS' ? '#34D399' : k === 'FAIL' ? '#F87171' : '#FBBF24',
                        }} />
                      ))}
                    </div>
                    {failuresByArea.length > 0 ? (
                      <div className="grid gap-1.5 sm:grid-cols-2">
                        {failuresByArea.map(([k, n]) => (
                          <div key={k} className="flex items-center gap-2 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5 text-[11px]">
                            <TriangleAlert size={12} className="text-rose-300" aria-hidden="true" />
                            <span className="text-slate-300">{AREA_LABEL[k] ?? k}</span>
                            <span className="ml-auto font-mono tnum text-rose-300">{n} failed</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="flex items-center gap-1.5 text-[11px] text-emerald-300">
                        <FileCheck2 size={13} aria-hidden="true" /> No failed controls in this run.
                      </p>
                    )}
                  </div>
                )}
              </div>

              <div className="card">
                <div className="mb-2 flex flex-wrap items-end gap-2">
                  <h2 className="text-[13px]">Rule results</h2>
                  <span className="font-mono text-[10px] text-slate-500">{filtered.length} of {results.length}</span>
                  <div className="ml-auto flex flex-wrap gap-1.5">
                    <select aria-label="Filter by outcome" className="input w-auto py-1 text-[11px]" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
                      {OUTCOMES.map((o) => <option key={o} value={o}>{o === 'ALL' ? 'All outcomes' : o}</option>)}
                    </select>
                    <select aria-label="Filter by severity" className="input w-auto py-1 text-[11px]" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s === 'ALL' ? 'All severities' : s}</option>)}
                    </select>
                    <select aria-label="Filter by control area" className="input w-auto py-1 text-[11px]" value={area} onChange={(e) => setArea(e.target.value)}>
                      <option value="ALL">All areas</option>
                      {areas.map((a) => <option key={a} value={a}>{AREA_LABEL[a] ?? a}</option>)}
                    </select>
                    <select aria-label="Filter by detection source" className="input w-auto py-1 text-[11px]" value={source} onChange={(e) => setSource(e.target.value)}>
                      {SOURCES.map((s) => <option key={s} value={s}>{s === 'ALL' ? 'All sources' : s === 'vulnerability' ? 'Known CVEs' : 'Configuration'}</option>)}
                    </select>
                    <input aria-label="Search results" className="input w-40 py-1 text-[11px]" placeholder="Rule, asset, evidence…" value={q} onChange={(e) => setQ(e.target.value)} />
                  </div>
                </div>
                {loadingResults ? <Loading msg="Loading rule results" /> : (
                  <div className="tblwrap max-h-[30rem] overflow-y-auto">
                    <table className="tbl min-w-[780px]">
                      <thead>
                        <tr><th>Control</th><th>Source</th><th>Area</th><th>Asset</th><th>Outcome</th><th>Severity</th><th>Evidence</th></tr>
                      </thead>
                      <tbody>
                        {filtered.map((r, i) => (
                          <tr key={`${r.rule_id}-${r.asset_id}-${i}`}>
                            <td className="font-mono text-[11px] text-slate-200">
                              {sourceOf(r) === 'vulnerability' ? (
                                <a className="text-accent-soft hover:underline" target="_blank" rel="noreferrer"
                                  href={`https://nvd.nist.gov/vuln/detail/${r.rule_id}`}>{r.rule_id}</a>
                              ) : r.rule_id}
                            </td>
                            <td><Badge text={sourceOf(r) === 'vulnerability' ? 'CVE' : 'Config'} /></td>
                            <td className="text-[11px] text-slate-400">{AREA_LABEL[areaOf(r.rule_id)] ?? areaOf(r.rule_id)}</td>
                            <td className="max-w-[10rem] truncate text-slate-300">{assetName(r.asset_id)}</td>
                            <td><Badge text={String(r.outcome)} /></td>
                            <td><Badge text={String(r.severity)} /></td>
                            <td className="max-w-[16rem] truncate font-mono text-[10.5px] text-slate-500" title={r.evidence_ref}>{r.evidence_ref || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {filtered.length === 0 && (
                      <p className="py-4 text-center text-[12px] text-slate-500">
                        {results.length === 0 ? 'This run recorded no rule results.' : 'No results match the current filters.'}
                      </p>
                    )}
                  </div>
                )}
                <p className="mt-2 text-[10.5px] text-slate-500">
                  Outcomes are evidence-backed: PASS/FAIL require recorded evidence, UNKNOWN marks missing evidence rather than assumed security.
                  CVE results are version matches from a bundled advisory snapshot — evidence to verify, not proof of exploitability.
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </Page>
  );
}
