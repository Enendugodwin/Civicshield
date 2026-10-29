import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Bot } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

export default function Proposals() {
  const [params] = useSearchParams();
  const [list, setList] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [rels, setRels] = useState<any[]>([]);
  const [title, setTitle] = useState('');
  const [rationale, setRationale] = useState('');
  const [detail, setDetail] = useState<any>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  // change builder state
  const [op, setOp] = useState('remove_edge');
  const [relId, setRelId] = useState('');
  const [srcId, setSrcId] = useState('');
  const [tgtId, setTgtId] = useState('');
  const [relName, setRelName] = useState('depends_on');
  const [assetId, setAssetId] = useState('');
  const [zone, setZone] = useState('');
  const [crit, setCrit] = useState('');
  // simulate state
  const [blockEntry, setBlockEntry] = useState('');
  const [blockTarget, setBlockTarget] = useState('');
  const [mustBlock, setMustBlock] = useState<any[]>([]);
  const [mustKeep, setMustKeep] = useState<number[]>([]);
  const [keepPick, setKeepPick] = useState('');
  const [note, setNote] = useState('');

  const load = async (openId?: number) => {
    try {
      const [p, a, r] = await Promise.all([
        api.get('/api/architecture/proposals'),
        api.get('/api/assets').catch(() => []),
        api.get('/api/relationships').catch(() => []),
      ]);
      const items = p.items ?? p ?? [];
      setList(items);
      setAssets(a.items ?? a ?? []);
      setRels(r.items ?? r ?? []);
      if (openId) {
        const found = items.find((x: any) => x.id === openId);
        if (found) setDetail(found);
      } else if (detail) {
        const found = items.find((x: any) => x.id === detail.id);
        if (found) setDetail(found);
      }
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };
  useEffect(() => {
    const open = Number(params.get('open'));
    load(Number.isFinite(open) && open > 0 ? open : undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const create = async () => {
    setErr(''); setBusy(true);
    try {
      const p = await api.post('/api/architecture/proposals', { title, rationale });
      setTitle(''); setRationale('');
      await load(p.id);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const act = async (fn: () => Promise<any>) => {
    setErr(''); setBusy(true);
    try { await fn(); await load(detail?.id); }
    catch (e: any) { setErr(String(e?.message ?? e)); } finally { setBusy(false); }
  };
  const addChange = () => act(async () => {
    const payload = op === 'remove_edge' ? { relationship_id: Number(relId) }
      : op === 'add_edge' ? { source_type: 'asset', source_id: Number(srcId), target_type: 'asset', target_id: Number(tgtId), rel: relName.trim() }
      : { asset_id: Number(assetId), ...(zone ? { zone } : {}), ...(crit ? { criticality: crit } : {}) };
    await api.post(`/api/architecture/proposals/${detail.id}/changes`, { op, payload });
  });
  const simulate = () => act(() => api.post(`/api/architecture/proposals/${detail.id}/simulate`, { must_block: mustBlock, must_keep: mustKeep.map((relationship_id) => ({ relationship_id })) }));
  const assetName = (id: any) => assets.find((a: any) => String(a.id) === String(id))?.name ?? `#${id}`;

  const lastSim = detail?.sim_runs?.length ? detail.sim_runs[detail.sim_runs.length - 1].result : null;
  const draft = detail?.status === 'draft';
  const simulated = detail?.status === 'simulated';
  const approved = detail?.status === 'approved';
  const sel = 'input w-full sm:max-w-[220px]';

  return (
    <Page title="Proposals" crumb="CivicShield / Security Workflow / Proposals"
      actions={<span className="text-[10.5px] uppercase tracking-[0.07em] text-slate-500">
        {list.length} proposal{list.length === 1 ? '' : 's'} · simulations stay labeled
      </span>}>
      {err && <Err msg={err} />}
      <div className="grid gap-2 lg:grid-cols-[300px_1fr]">
        <div className="card grid content-start gap-2">
          <h3 className="text-[11px] uppercase tracking-wide text-slate-500">New proposal (operator)</h3>
          <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title, e.g. Segment the plant uplink" aria-label="Proposal title" />
          <textarea className="input" rows={2} value={rationale} onChange={(e) => setRationale(e.target.value)} placeholder="Rationale (optional)" aria-label="Rationale" />
          <button className="btn" onClick={create} disabled={busy || !title.trim()}>Create draft</button>
          <h3 className="mt-1 text-[11px] uppercase tracking-wide text-slate-500">All proposals</h3>
          {list.length === 0 ? <Empty msg="No proposals yet." /> : (
            <div className="grid gap-1">
              {list.map((p: any) => (
                <button key={p.id}
                  className={`flex flex-wrap items-center gap-2 rounded-md border px-2 py-1.5 text-left text-[12px] ${detail?.id === p.id ? 'border-accent/40 bg-accent/10' : 'border-line/60 bg-raised/30'}`}
                  onClick={() => setDetail(p)}>
                  <span className="font-mono text-slate-200">#{p.id}</span>
                  <span className="min-w-0 flex-1 truncate text-slate-300">{p.title}</span>
                  <Badge text={p.status} />
                </button>
              ))}
            </div>
          )}
        </div>

        {!detail ? <Empty msg="Select a proposal to stage edits, simulate, and apply." /> : (
          <div className="grid content-start gap-2">
            <div className="card grid gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-slate-100">#{detail.id} {detail.title}</span>
                <Badge text={detail.status} />
                <span className="ml-auto flex flex-wrap gap-1.5">
                  <Link className="btn-sec" title="Ask the assistant to explain this proposal"
                    to={`/assistant?q=${encodeURIComponent(`Explain proposal #${detail.id}`)}`}>
                    <Bot size={12} aria-hidden="true" /> Explain with AI
                  </Link>
                  <input className="input max-w-44 !py-1" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Decision note" aria-label="Decision note" />
                  {simulated && <button className="btn-sec" onClick={() => act(() => api.post(`/api/architecture/proposals/${detail.id}/approve`, { note }))} disabled={busy}>Approve</button>}
                  {approved && <button className="btn" onClick={() => act(() => api.post(`/api/architecture/proposals/${detail.id}/apply`, {}))} disabled={busy}>Apply to live</button>}
                  {(draft || simulated || approved) && (
                    <button className="btn-sec" onClick={() => act(() => api.post(`/api/architecture/proposals/${detail.id}/reject`, { note }))} disabled={busy}>Reject</button>
                  )}
                </span>
              </div>
              {detail.rationale && <p className="text-[12px] text-slate-400">{detail.rationale}</p>}
              <div className="text-[11px] text-slate-500">
                Lifecycle: draft → simulated → approved → applied. Simulation runs on a snapshot copy;
                a passing simulation does not prove the change works in production.
              </div>
            </div>

            <div className="card grid gap-2">
              <h3 className="text-[11px] uppercase tracking-wide text-slate-500">Staged edits ({detail.changes.length})</h3>
              {detail.changes.map((c: any) => (
                <div key={c.id} className="flex flex-wrap items-center gap-2 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5 text-[11.5px]">
                  <span className="font-mono text-slate-200">{c.op}</span>
                  <span className="font-mono text-[10.5px] text-slate-400">{JSON.stringify(c.payload)}</span>
                  {draft && (
                    <button className="btn-sec ml-auto !px-2 !py-0.5 !text-[10px]"
                      onClick={() => act(() => api.del(`/api/architecture/proposals/${detail.id}/changes/${c.id}`))}>Remove</button>
                  )}
                </div>
              ))}
              {draft && (
                <div className="grid gap-2 rounded-md border border-line/60 p-2">
                  <div className="flex flex-wrap gap-2">
                    {['remove_edge', 'add_edge', 'update_asset'].map((o) => (
                      <button key={o} className={`btn-sec ${op === o ? '!border-accent/50' : ''}`} onClick={() => setOp(o)}>{o}</button>
                    ))}
                  </div>
                  {op === 'remove_edge' && (
                    <select className={sel} value={relId} onChange={(e) => setRelId(e.target.value)} aria-label="Edge to remove">
                      <option value="">Pick an edge…</option>
                      {rels.filter((r: any) => r.source_type === 'asset' && r.target_type === 'asset').map((r: any) => (
                        <option key={r.id} value={r.id}>#{r.id} {assetName(r.source_id)} —{r.rel}→ {assetName(r.target_id)}</option>
                      ))}
                    </select>
                  )}
                  {op === 'add_edge' && (
                    <div className="flex flex-wrap gap-2">
                      <select className={sel} value={srcId} onChange={(e) => setSrcId(e.target.value)} aria-label="Edge source">
                        <option value="">Source…</option>{assets.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
                      </select>
                      <select className={sel} value={tgtId} onChange={(e) => setTgtId(e.target.value)} aria-label="Edge target">
                        <option value="">Target…</option>{assets.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
                      </select>
                      <select className="input max-w-44" value={relName} onChange={(e) => setRelName(e.target.value)} aria-label="Relation">
                        {['depends_on', 'connects_to', 'authenticates_via', 'manages', 'monitors', 'backs_up', 'serves'].map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </div>
                  )}
                  {op === 'update_asset' && (
                    <div className="flex flex-wrap gap-2">
                      <select className={sel} value={assetId} onChange={(e) => setAssetId(e.target.value)} aria-label="Asset to update">
                        <option value="">Asset…</option>{assets.map((a: any) => <option key={a.id} value={a.id}>{a.name} ({a.zone}/{a.criticality})</option>)}
                      </select>
                      <select className="input max-w-36" value={zone} onChange={(e) => setZone(e.target.value)} aria-label="New zone">
                        <option value="">Zone…</option>{['core', 'office', 'plant', 'dmz', 'central', 'edge', 'external'].map((z) => <option key={z} value={z}>{z}</option>)}
                      </select>
                      <select className="input max-w-36" value={crit} onChange={(e) => setCrit(e.target.value)} aria-label="New criticality">
                        <option value="">Criticality…</option>{['critical', 'high', 'medium', 'low'].map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>
                  )}
                  <div><button className="btn-sec" onClick={addChange} disabled={busy}>Stage edit</button></div>
                </div>
              )}
            </div>

            <div className="card grid gap-2">
              <h3 className="text-[11px] uppercase tracking-wide text-slate-500">Simulate before / after</h3>
              {(draft || simulated) && (
                <div className="grid gap-2 rounded-md border border-line/60 p-2">
                  <div className="flex flex-wrap items-end gap-2">
                    <label className="grid gap-1 text-[11px] text-slate-500">must_block entry
                      <select className={sel} value={blockEntry} onChange={(e) => setBlockEntry(e.target.value)} aria-label="Blocked entry">
                        <option value="">Entry…</option>{assets.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
                      </select>
                    </label>
                    <label className="grid gap-1 text-[11px] text-slate-500">must_block target
                      <select className={sel} value={blockTarget} onChange={(e) => setBlockTarget(e.target.value)} aria-label="Blocked target">
                        <option value="">Target…</option>{assets.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
                      </select>
                    </label>
                    <button className="btn-sec" onClick={() => {
                      if (blockEntry && blockTarget) {
                        setMustBlock([...mustBlock, { entry_asset_id: Number(blockEntry), target_asset_id: Number(blockTarget) }]);
                        setBlockEntry(''); setBlockTarget('');
                      }
                    }}>Add criterion</button>
                    <label className="grid gap-1 text-[11px] text-slate-500">must_keep edge
                      <select className={sel} value={keepPick} onChange={(e) => setKeepPick(e.target.value)} aria-label="Kept edge">
                        <option value="">Edge…</option>
                        {rels.filter((r: any) => r.source_type === 'asset' && r.target_type === 'asset').map((r: any) => (
                          <option key={r.id} value={r.id}>#{r.id} {assetName(r.source_id)} —{r.rel}→ {assetName(r.target_id)}</option>
                        ))}
                      </select>
                    </label>
                    <button className="btn-sec" onClick={() => {
                      if (keepPick && !mustKeep.includes(Number(keepPick))) setMustKeep([...mustKeep, Number(keepPick)]);
                      setKeepPick('');
                    }}>Add</button>
                  </div>
                  {(mustBlock.length > 0 || mustKeep.length > 0) && (
                    <div className="flex flex-wrap gap-1.5 text-[11px]">
                      {mustBlock.map((b, i) => (
                        <button key={i} className="badge" title="Remove criterion"
                          onClick={() => setMustBlock(mustBlock.filter((_, j) => j !== i))}>
                          block {assetName(b.entry_asset_id)} → {assetName(b.target_asset_id)} ✕
                        </button>
                      ))}
                      {mustKeep.map((id) => (
                        <button key={id} className="badge" title="Remove criterion"
                          onClick={() => setMustKeep(mustKeep.filter((x) => x !== id))}>keep #{id} ✕</button>
                      ))}
                      <button className="btn ml-auto" onClick={simulate} disabled={busy}>Run simulation</button>
                    </div>
                  )}
                  {mustBlock.length === 0 && mustKeep.length === 0 && (
                    <div><button className="btn" onClick={simulate} disabled={busy}>Run simulation (no criteria)</button></div>
                  )}
                </div>
              )}
              {lastSim ? (
                <div className="grid gap-1.5 text-[12px]">
                  <div className="text-slate-300">
                    Baseline <strong>{lastSim.baseline.hits} hits / {lastSim.baseline.paths} paths</strong>
                    {' '}→ simulated <strong>{lastSim.simulated.hits} hits / {lastSim.simulated.paths} paths</strong>
                    {' '}· <span className="font-mono text-[10.5px] text-amber-300">{lastSim.label}</span>
                  </div>
                  <div className="grid gap-1 sm:grid-cols-2">
                    <div className="rounded-md border border-line/60 bg-raised/30 p-2">
                      <div className="section-label">Hits resolved ({lastSim.hits_resolved.length})</div>
                      {lastSim.hits_resolved.map((h: any, i: number) => <div key={i} className="font-mono text-emerald-300">− {h[0]} on asset {h[1]}</div>)}
                      {lastSim.hits_resolved.length === 0 && <div className="text-slate-500">none</div>}
                    </div>
                    <div className="rounded-md border border-line/60 bg-raised/30 p-2">
                      <div className="section-label">Hits added ({lastSim.hits_added.length})</div>
                      {lastSim.hits_added.map((h: any, i: number) => <div key={i} className="font-mono text-red-300">+ {h[0]} on asset {h[1]}</div>)}
                      {lastSim.hits_added.length === 0 && <div className="text-slate-500">none</div>}
                    </div>
                  </div>
                  <div className="text-slate-400">
                    Paths removed: <strong className="text-slate-200">{lastSim.paths_removed}</strong>
                    {' '}· added: <strong className="text-slate-200">{lastSim.paths_added}</strong>
                    {lastSim.removed_path_endpoints.length > 0 && (
                      <span className="font-mono text-[10.5px]"> ({lastSim.removed_path_endpoints.map((e: any) => `${e[0]}→${e[1]}`).join(', ')})</span>
                    )}
                  </div>
                  {lastSim.warnings.length > 0 && (
                    <div className="text-[11px] text-amber-300">{lastSim.warnings.join(' · ')}</div>
                  )}
                  <div className="grid gap-1">
                    {lastSim.verification.map((v: any, i: number) => (
                      <div key={i} className={`rounded-md border px-2 py-1.5 ${v.passed ? 'border-emerald-500/40 text-emerald-200' : 'border-red-500/40 text-red-200'}`}>
                        {v.passed ? 'PASS' : 'FAIL'} · {v.criterion}{' '}
                        {v.criterion === 'must_block'
                          ? `${assetName(v.entry_asset_id)} → ${assetName(v.target_asset_id)}`
                          : `#${v.relationship_id}`} — {v.note}
                      </div>
                    ))}
                    {lastSim.verification.length > 0 && (
                      <div className="text-[11.5px] text-slate-400">
                        Verification {lastSim.verification_passed ? 'passed' : 'did not pass'}.
                      </div>
                    )}
                  </div>
                  <div className="text-[10.5px] text-slate-500">
                    {detail.sim_runs.length} simulation run{detail.sim_runs.length === 1 ? '' : 's'} stored on this proposal.
                  </div>
                </div>
              ) : (
                <Empty msg="No simulation yet. Stage edits, add criteria, run the simulation." />
              )}
            </div>

            <Link className="btn-sec w-fit" to="/map">Open infrastructure map</Link>
          </div>
        )}
      </div>
    </Page>
  );
}
