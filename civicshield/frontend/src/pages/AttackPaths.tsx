import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Bot, Route, ShieldAlert } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

export default function AttackPaths() {
  const navigate = useNavigate();
  const [assets, setAssets] = useState<any[]>([]);
  const [entry, setEntry] = useState('');
  const [target, setTarget] = useState('');
  const [depth, setDepth] = useState(5);
  const [result, setResult] = useState<any>(null);
  const [excluded, setExcluded] = useState<number[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const [initial, setInitial] = useState(true);

  useEffect(() => {
    api.get('/api/assets').then((d: any) => setAssets(d.items ?? d ?? [])).catch(() => {});
  }, []);

  const analyze = async (excl?: number[]) => {
    setErr(''); setLoading(true);
    try {
      const r = await api.post('/api/analysis/attack-paths', {
        entry_asset_id: entry ? Number(entry) : null,
        target_asset_id: target ? Number(target) : null,
        max_depth: Number(depth) || 5,
        max_paths: 5,
        exclude_edge_ids: excl ?? excluded,
      });
      setResult(r);
      setInitial(false);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setLoading(false); }
  };

  useEffect(() => { analyze([]); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const excludeAndRerun = (id: number) => {
    if (!id || excluded.includes(id)) return;
    const next = [...excluded, id];
    setExcluded(next);
    analyze(next);
  };

  const assetName = (id: any) => assets.find((a) => String(a.id) === String(id))?.name ?? `Asset ${id}`;
  const sel = 'input w-full sm:max-w-[220px]';

  return (
    <Page title="Attack Paths" crumb="CivicShield / Security Workflow / Attack Paths"
      actions={<span className="text-[10.5px] uppercase tracking-[0.07em] text-slate-500">
        {result ? `${result.path_count} path${result.path_count === 1 ? '' : 's'} · v${result.analysis_version}` : 'defensive reachability'}
      </span>}>
      {err && <Err msg={err} />}
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-end">
        <label className="grid gap-1 text-[11px] text-slate-500">Entry point
          <select className={sel} value={entry} onChange={(e) => setEntry(e.target.value)} aria-label="Entry point">
            <option value="">Auto: external / edge assets</option>
            {assets.map((a: any) => <option key={a.id} value={a.id}>{a.name} ({a.zone})</option>)}
          </select>
        </label>
        <label className="grid gap-1 text-[11px] text-slate-500">Target
          <select className={sel} value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target asset">
            <option value="">Auto: high-value assets</option>
            {assets.filter((a: any) => ['critical', 'high'].includes(String(a.criticality))).map((a: any) => (
              <option key={a.id} value={a.id}>{a.name} ({a.criticality})</option>
            ))}
          </select>
        </label>
        <label className="grid gap-1 text-[11px] text-slate-500">Max hops
          <input className="input w-24" type="number" min={1} max={8} value={depth}
            onChange={(e) => setDepth(Number(e.target.value))} aria-label="Maximum hops" />
        </label>
        <button className="btn" onClick={() => analyze()} disabled={loading}>
          <Route size={14} aria-hidden="true" /> {loading ? 'Analyzing…' : 'Analyze paths'}
        </button>
        {excluded.length > 0 && (
          <button className="btn-sec" onClick={() => { setExcluded([]); analyze([]); }}>
            Clear {excluded.length} exclusion{excluded.length === 1 ? '' : 's'}
          </button>
        )}
        {excluded.length > 0 && (
          <button className="btn-sec" title="Stage these edge cuts as a change proposal"
            onClick={async () => {
              setErr('');
              try {
                const p = await api.post('/api/architecture/proposals', {
                  title: `Cut ${excluded.length} attack-path edge${excluded.length === 1 ? '' : 's'}`,
                  rationale: 'Staged from Attack Paths what-if exclusions.',
                });
                for (const id of excluded) {
                  await api.post(`/api/architecture/proposals/${p.id}/changes`, {
                    op: 'remove_edge', payload: { relationship_id: id },
                  });
                }
                navigate(`/proposals?open=${p.id}`);
              } catch (e: any) { setErr(String(e?.message ?? e)); }
            }}>
            Save as proposal
          </button>
        )}
      </div>

      {result && (
        <div className="card text-[12px] text-slate-400">
          From <strong className="text-slate-200">{result.entries.length} entr{result.entries.length === 1 ? 'y' : 'ies'}</strong>
          {' '}({result.entries.map((e: any) => e.name).slice(0, 4).join(', ')}{result.entries.length > 4 ? ', …' : ''})
          {' '}to <strong className="text-slate-200">{result.targets.length} high-value target{result.targets.length === 1 ? '' : 's'}</strong>.
          Every hop cites its relationship; assumed hops are flagged, never presented as confirmed exploits.
        </div>
      )}

      {loading && <Loading msg="Analyzing reachability" />}
      {!loading && !initial && result && result.paths.length === 0 && (
        <Empty msg={excluded.length ? 'No paths remain with these exclusions — the cut isolates the targets.' : 'No paths found between these points.'} />
      )}
      {!loading && result && (
        <div className="grid gap-2">
          {result.paths.map((p: any) => (
            <div key={`${p.entry_id}-${p.target_id}-${p.rank}`} className="card">
              <div className="flex flex-wrap items-center gap-2">
                <span className="badge">#{p.rank} score {p.rank_score}</span>
                <span className="font-semibold text-slate-100">{p.entry_name}</span>
                <span className="text-slate-500">→</span>
                <span className="font-semibold text-slate-100">{p.target_name}</span>
                <Badge text={String(p.target_criticality)} />
                {p.boundary_crossings > 0 && <Badge text={`${p.boundary_crossings} zone crossing${p.boundary_crossings === 1 ? '' : 's'}`} />}
                {p.assumed_hops > 0 && <Badge text={`${p.assumed_hops} assumed hop${p.assumed_hops === 1 ? '' : 's'}`} />}
                <span className="ml-auto font-mono text-[10px] text-slate-500">
                  {p.length} hop{p.length === 1 ? '' : 's'} · blast radius {p.blast_radius.asset_count} asset{p.blast_radius.asset_count === 1 ? '' : 's'}
                </span>
              </div>
              <ol className="mt-2 grid gap-1">
                {p.hops.map((h: any, i: number) => (
                  <li key={i} className="flex flex-wrap items-center gap-1.5 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5 text-[11.5px]">
                    <span className="text-slate-200">{h.from_name}</span>
                    <span className="font-mono text-slate-500">—{h.rel}→</span>
                    <span className="text-slate-200">{h.to_name}</span>
                    <span className={`badge ${h.connectivity === 'confirmed' ? '' : 'opacity-80'}`}>{h.connectivity}</span>
                    {h.trust_boundary && <span className="badge">zone {h.zone_from} → {h.zone_to}</span>}
                    {h.assumed && (
                      <span className="inline-flex items-center gap-1 text-amber-300" title={h.note}>
                        <ShieldAlert size={11} aria-hidden="true" /> assumed
                      </span>
                    )}
                    <button className="btn-sec ml-auto !px-2 !py-0.5 !text-[10px]" title="Re-run without this link (what-if comparison)"
                      onClick={() => excludeAndRerun(Number(h.relationship_id))}>
                      Exclude & re-run
                    </button>
                    <Link className="btn-sec !px-2 !py-0.5 !text-[10px]" title="Ask the assistant to explain this path"
                      to={`/assistant?q=${encodeURIComponent(`Explain attack path from asset #${p.entry_id} to asset #${p.target_id}`)}`}>
                      <Bot size={11} aria-hidden="true" /> Explain with AI
                    </Link>
                    <span className="basis-full text-[10.5px] text-slate-500">{h.note} · rel #{h.relationship_id} ({h.provenance})</span>
                  </li>
                ))}
              </ol>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
                <span className="section-label">Rank factors</span>
                <span className="font-mono">
                  hops {p.rank_factors.hops} · findings {p.rank_factors.critical_high_findings} · target {p.rank_factors.target_criticality} · crossings {p.rank_factors.boundary_crossings} · assumed {p.rank_factors.assumed_hops}
                </span>
              </div>
              {p.open_findings_count > 0 && (
                <div className="mt-1 text-[11px] text-slate-400">
                  <span className="section-label mr-1">Known open findings on path</span>
                  {p.open_findings.slice(0, 6).map((f: any) => (
                    <Link key={f.finding_id} className="mr-1.5 font-mono text-accent-soft hover:underline"
                      to={`/findings`} title={`${assetName(f.asset_id)} — ${f.severity}`}>{f.rule_id}</Link>
                  ))}
                  {p.open_findings_count > 6 && <span className="text-slate-500">+{p.open_findings_count - 6} more</span>}
                </div>
              )}
              {(p.blast_radius.services ?? p.blast_radius.service_ids ?? []).length > 0 && (
                <div className="mt-1 text-[11px] text-slate-500">
                  Services in blast radius: {(p.blast_radius.services ?? p.blast_radius.service_ids ?? []).map((s: any) => typeof s === 'string' ? s : s.name).join(', ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Page>
  );
}
