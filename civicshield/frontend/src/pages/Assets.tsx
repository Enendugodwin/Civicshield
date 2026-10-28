import { useEffect, useState } from 'react';
import { Radar, ShieldAlert, Terminal } from 'lucide-react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

const SAMPLE = 'name,kind,hostname,owner,os_name,environment,zone,criticality,criticality_reason,status\npump-02,pump,pump02,ops-team,Ubuntu 22.04,operations,central,high,,operational';

export default function Assets() {
  const [items, setItems] = useState<any[]>([]);
  const [q, setQ] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<any>(null);
  const [csv, setCsv] = useState('');
  const [preview, setPreview] = useState<any>(null);
  const [form, setForm] = useState({ name: '', kind: 'server', hostname: '', owner: '', criticality: 'moderate', zone: 'central' });
  const [posture, setPosture] = useState<any>(null);
  const [detecting, setDetecting] = useState<number | 'all' | null>(null);
  const [result, setResult] = useState<any>(null);
  const load = () => {
    setLoading(true);
    api.get('/api/assets').then((d: any) => setItems(d.items ?? d ?? [])).catch((e) => setErr(String(e))).finally(() => setLoading(false));
  };
  const loadPosture = () => api.get('/api/detection/posture').then(setPosture).catch(() => null);
  useEffect(() => { load(); loadPosture(); }, []);
  const detect = async (id: number | 'all') => {
    setErr(''); setResult(null); setDetecting(id);
    try {
      const r: any = id === 'all'
        ? await api.post('/api/detect', {})
        : await api.post(`/api/assets/${id}/detect`, {});
      setResult(r);
      await loadPosture();
    } catch (e: any) { setErr(String(e?.message ?? e)); }
    finally { setDetecting(null); }
  };
  const evidenceOf = (id: number) => (posture?.assets ?? []).find((x: any) => x.asset_id === id);
  const create = async () => {
    setErr('');
    try {
      await api.post('/api/assets', form);
      setForm({ name: '', kind: 'server', hostname: '', owner: '', criticality: 'moderate', zone: 'central' });
      load();
    } catch (e: any) { setErr(String(e)); }
  };
  const saveEdit = async () => {
    try { await api.patch(`/api/assets/${editing.id}`, editing); setEditing(null); load(); }
    catch (e: any) { setErr(String(e)); }
  };
  const retire = async (id: number) => {
    if (!confirm(`Retire asset ${id}? It stays in history but leaves active inventory.`)) return;
    try { await api.del(`/api/assets/${id}`); load(); } catch (e: any) { setErr(String(e)); }
  };
  const doPreview = async () => {
    setErr(''); setPreview(null);
    try { setPreview(await api.post('/api/assets/import', { csv_text: csv, dry_run: true })); }
    catch (e: any) { setErr(String(e)); }
  };
  const doCommit = async () => {
    try {
      const r = await api.post('/api/assets/import', { csv_text: csv, dry_run: false });
      setPreview(r); setCsv(''); load();
    } catch (e: any) { setErr(String(e)); }
  };
  const filtered = items.filter((x) => JSON.stringify(x).toLowerCase().includes(q.toLowerCase()));
  return (
    <Page title="Asset Inventory" crumb="CivicShield / Infrastructure / Assets"
      actions={<span className="text-[11px] text-slate-500">{filtered.length} of {items.length} assets</span>}>
      {err && <Err msg={err} />}
      <div className="card">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <Radar size={15} className="text-accent-soft" aria-hidden="true" />
          <h2 className="text-[13px]">Detection</h2>
          <span className="text-[10px] text-slate-500">
            collector coverage {posture ? `${posture.assets_current}/${posture.assets_total}` : '…'}
          </span>
          <button className="btn ml-auto" onClick={() => detect('all')} disabled={detecting !== null}>
            <ShieldAlert size={13} aria-hidden="true" />
            {detecting === 'all' ? 'Detecting…' : 'Detect all assets'}
          </button>
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
            <div className="kpi-label">Evidence current</div>
            <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">
              {posture ? `${posture.assets_current}/${posture.assets_total}` : '—'}
            </div>
            <div className="text-[10px] text-slate-500">
              {posture ? `${posture.assets_stale} stale · ${posture.assets_never} never collected` : 'loading'}
            </div>
          </div>
          <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
            <div className="kpi-label">Advisory snapshot</div>
            <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">{posture?.advisories?.count ?? '—'}</div>
            <div className="text-[10px] text-slate-500">known CVEs · {posture?.advisories?.snapshot ?? 'loading'}</div>
          </div>
          <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
            <div className="kpi-label">Last detection</div>
            <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">
              {posture?.last_run ? `#${posture.last_run.id}` : '—'}
            </div>
            <div className="text-[10px] text-slate-500">{posture?.last_run?.scope ?? 'no run yet'}</div>
          </div>
        </div>
        {result && (
          <div className="mt-2 rounded-md border border-accent/25 bg-accent/[0.06] px-2.5 py-2 text-[11.5px] text-slate-300">
            Detection {result.scope ? `(${result.scope})` : ''}: {result.outcomes?.FAIL ?? 0} failed checks,{' '}
            <strong className="text-rose-300">{result.vulnerabilities ?? 0} vulnerability matches</strong>{' '}
            ({result.critical_vulnerabilities ?? 0} critical)
            {result.findings?.length > 0 && (
              <span className="text-slate-400"> · top: {result.findings.filter((f: any) => f.source === 'vulnerability').slice(0, 2).map((f: any) => f.rule_id).join(', ') || 'none'}</span>
            )}
          </div>
        )}
        <details className="mt-2">
          <summary className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-slate-400">
            <Terminal size={12} aria-hidden="true" /> Run the read-only collector on an authorized host
          </summary>
          <pre className="mt-1.5 overflow-x-auto rounded-md border border-line/70 bg-black/30 p-2 font-mono text-[10.5px] text-slate-300">{`python backend/agent/civicshield_agent.py collect \\
  --asset-id <asset-id> --push --run-detection \\
  --api http://127.0.0.1:8000 --token operator`}</pre>
          <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">
            The agent collects OS, patch, firewall, privileged accounts, endpoint and package evidence with read-only commands.
            It does not scan the network or change the host. Missing evidence is reported as unknown.
          </p>
        </details>
      </div>
      <input className="input" placeholder="Search / filter" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search assets" />
      <div className="card grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
        {(['name', 'kind', 'hostname', 'owner', 'criticality', 'zone'] as const).map((k) => (
          <label key={k} className="grid gap-1 text-[11px] text-slate-500 capitalize">{k}
            <input className="input" value={(form as any)[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} />
          </label>
        ))}
        <div className="flex items-end"><button className="btn w-full" onClick={create} disabled={!form.name}>Create asset</button></div>
      </div>
      <div className="card grid gap-2">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-500">CSV import (max 200 rows, 256 KB) — preview before accepting</h3>
        <textarea className="input font-mono" rows={4} placeholder={SAMPLE} value={csv} onChange={(e) => setCsv(e.target.value)} aria-label="CSV text" />
        <div className="flex gap-2 flex-wrap">
          <button className="btn-sec" onClick={doPreview} disabled={!csv}>Validate & preview</button>
          {preview && preview.errors.length === 0 && <button className="btn" onClick={doCommit}>Accept {preview.valid} rows</button>}
        </div>
        {preview && (
          <div className="text-[12px] text-slate-300">Valid: {preview.valid} · Errors: {preview.errors.length}
            {preview.errors.slice(0, 5).map((e: any, i: number) => <div key={i} className="text-red-300">Row {e.row}: {e.error}</div>)}
            {preview.created_ids?.length > 0 && <div className="text-emerald-300">Created IDs: {preview.created_ids.join(', ')}</div>}
          </div>
        )}
      </div>
      {loading ? <Loading msg="Loading assets" /> : filtered.length === 0 ? <Empty msg="No assets match." /> : (
        <div className="tblwrap p-2 overflow-x-auto"><table className="tbl min-w-[920px]">
          <thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Owner</th><th>Criticality</th><th>Status</th><th>Evidence</th><th>Detection</th><th></th></tr></thead>
          <tbody>{filtered.map((x: any) => (
            editing?.id === x.id ? (
              <tr key={x.id}>
                <td className="text-slate-500">{x.id}</td>
                <td className="text-slate-100">{x.hostname || x.name}</td>
                <td className="text-slate-400">{x.kind}</td>
                <td><input className="input" value={editing.owner ?? ''} onChange={(e) => setEditing({ ...editing, owner: e.target.value })} aria-label="Owner" /></td>
                <td><select className="input" value={editing.criticality ?? 'low'} onChange={(e) => setEditing({ ...editing, criticality: e.target.value })} aria-label="Criticality">
                  <option value="low">low</option><option value="moderate">moderate</option><option value="high">high</option><option value="critical">critical</option>
                </select></td>
                <td><select className="input" value={editing.status ?? 'operational'} onChange={(e) => setEditing({ ...editing, status: e.target.value })} aria-label="Status">
                  <option value="operational">operational</option><option value="degraded">degraded</option><option value="recovering">recovering</option>
                </select></td>
                <td><Badge text={evidenceOf(x.id)?.state ?? 'never'} /></td>
                <td><button className="btn-sec" onClick={() => detect(x.id)} disabled={detecting !== null}>
                  {detecting === x.id ? 'Detecting…' : 'Detect'}
                </button></td>
                <td className="whitespace-nowrap"><button className="btn-sec mr-1" onClick={saveEdit}>Save</button>
                  <button className="btn-sec" onClick={() => setEditing(null)}>Cancel</button></td>
              </tr>
            ) : (
              <tr key={x.id}><td className="text-slate-500">{x.id}</td><td className="text-slate-100 font-semibold">{x.hostname || x.name}</td>
                <td className="text-slate-400">{x.kind}</td><td className="text-slate-400">{x.owner || '—'}</td>
                <td><Badge text={String(x.criticality ?? 'unknown')} /></td><td><Badge text={String(x.status ?? 'unknown')} /></td>
                <td>
                  <Badge text={evidenceOf(x.id)?.state ?? 'never'} />
                  <span className="ml-1 text-[10px] text-slate-500">
                    {evidenceOf(x.id)?.age_hours != null ? `${Math.round(evidenceOf(x.id).age_hours)}h` : ''}
                  </span>
                </td>
                <td><button className="btn-sec" onClick={() => detect(x.id)} disabled={detecting !== null}>
                  {detecting === x.id ? 'Detecting…' : 'Detect'}
                </button></td>
                <td className="whitespace-nowrap"><button className="btn-sec mr-1" onClick={() => setEditing({ id: x.id, owner: x.owner ?? '', criticality: x.criticality ?? 'low', status: x.status ?? 'operational' })}>Edit</button>
                  <button className="btn-sec" onClick={() => retire(x.id)}>Retire</button></td></tr>
            )
          ))}</tbody>
        </table></div>
      )}
    </Page>
  );
}
