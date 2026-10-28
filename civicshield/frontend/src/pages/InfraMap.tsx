import { useEffect, useMemo, useState } from 'react';
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';
import { Plus, Router, Network, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { Err, Loading, Page } from '../components/ui';

const CRIT = '#ef4444';
const LINE = '#26344D';
const KIND_COLOR: Record<string, string> = {
  router: '#38BDF8',
  switch: '#34D399',
  firewall: '#F59E0B',
  server: '#A78BFA',
  database: '#60A5FA',
  directory: '#F472B6',
  monitoring: '#2DD4BF',
  backup: '#FBBF24',
  workstation: '#94A3B8',
  external: '#64748B',
};
const KIND_ORDER = Object.keys(KIND_COLOR);
const ZONE_ORDER = ['edge', 'core', 'plant', 'office', 'external'];
const zoneRank = (z: string) => {
  const i = ZONE_ORDER.indexOf(String(z));
  return i < 0 ? ZONE_ORDER.length : i;
};

const REL_COLOR: Record<string, string> = {
  depends_on: '#34D399',
  backed_by: '#FBBF24',
  authenticates_via: '#C084FC',
  supplies: '#60A5FA',
};

export default function InfraMap() {
  const [assets, setAssets] = useState<any[]>([]);
  const [services, setServices] = useState<any[]>([]);
  const [rels, setRels] = useState<any[]>([]);
  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [rel, setRel] = useState({ source_type: 'asset', source_id: '', target_type: 'asset', target_id: '', rel: 'depends_on' });
  const [showAdd, setShowAdd] = useState(() => new URLSearchParams(window.location.search).get('add') === '1');
  const [adding, setAdding] = useState(false);
  const [notice, setNotice] = useState('');
  const [device, setDevice] = useState({
    name: '', kind: 'switch', hostname: '', owner: 'net-team', zone: 'core',
    criticality: 'high', status: 'operational', os_name: '',
  });

  const load = () => {
    setLoading(true);
    Promise.all([api.get('/api/assets').catch(() => []), api.get('/api/relationships').catch(() => []), api.get('/api/services').catch(() => [])])
      .then(([a, r, s]) => {
        const nextAssets: any[] = a.items ?? a ?? [];
        const nextRels: any[] = r.items ?? r ?? [];
        const nextServices: any[] = s.items ?? s ?? [];
        setAssets(nextAssets); setRels(nextRels); setServices(nextServices);

        const ordered = [...nextAssets].sort((x, y) =>
          zoneRank(x.zone) - zoneRank(y.zone) ||
          (KIND_ORDER.indexOf(x.kind) < 0 ? 99 : KIND_ORDER.indexOf(x.kind)) -
          (KIND_ORDER.indexOf(y.kind) < 0 ? 99 : KIND_ORDER.indexOf(y.kind)));
        const perRow = 4;
        const assetNodes = ordered.map((x: any, i: number) => {
          const accent = KIND_COLOR[x.kind] ?? '#94A3B8';
          const border = (x.criticality === 'critical' || x.status !== 'operational') ? CRIT : accent + '99';
          return {
            id: `a-${x.id}`,
            position: { x: (i % perRow) * 235, y: Math.floor(i / perRow) * 132 },
            data: {
              label: (
                <div className="text-left leading-tight">
                  <div className="text-[9px] uppercase tracking-[0.08em]" style={{ color: accent }}>{x.kind}</div>
                  <div className="font-mono text-[11px] text-slate-100">{x.hostname || x.name || x.id}</div>
                  <div className="text-[9px] text-slate-500">{x.zone} · {x.criticality}</div>
                </div>
              ),
            },
            style: {
              border: `${x.criticality === 'critical' ? 2 : 1}px solid ${border}`,
              borderRadius: 7, padding: '7px 9px', background: '#192134', color: '#e2e8f0',
              width: 180, boxShadow: '0 1px 0 rgba(255,255,255,0.03)',
            },
          };
        });

        const baseY = Math.ceil(ordered.length / perRow) * 132 + 70;
        const svcNodes = nextServices.map((x: any, i: number) => ({
          id: `s-${x.id}`, position: { x: (i % perRow) * 235, y: baseY },
          data: { label: `${x.name} · essential service` },
          style: { border: '1px dashed #34D399', borderRadius: 7, padding: '7px 9px', background: '#13251f', color: '#d1fae5', fontSize: 11 },
        }));

        const known = new Set([...assetNodes, ...svcNodes].map((n: any) => n.id));
        const nextEdges = nextRels
          .map((e: any, i: number) => ({
            id: String(e.id ?? i),
            source: `${e.source_type === 'service' ? 's' : 'a'}-${e.source_id}`,
            target: `${e.target_type === 'service' ? 's' : 'a'}-${e.target_id}`,
            label: e.rel ?? '',
            animated: ['backed_by', 'depends_on'].includes(e.rel),
            style: { stroke: REL_COLOR[e.rel] ?? '#34D399', strokeWidth: 1.4 },
            labelStyle: { fill: '#94A3B8', fontSize: 9 },
            labelBgStyle: { fill: '#192134', fillOpacity: 0.9 },
          }))
          .filter((e: any) => known.has(e.source) && known.has(e.target));

        setNodes([...assetNodes, ...svcNodes]);
        setEdges(nextEdges);
      })
      .catch((e) => setErr(String(e))).finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const addDevice = async () => {
    if (!device.name.trim()) return;
    setErr(''); setNotice(''); setAdding(true);
    try {
      const created: any = await api.post('/api/assets', {
        ...device,
        name: device.name.trim(),
        hostname: device.hostname.trim(),
        owner: device.owner.trim(),
        os_name: device.os_name.trim(),
        environment: device.zone === 'plant' ? 'operations' : device.zone,
        criticality_reason: device.criticality === 'critical'
          ? 'Manually registered critical network or service dependency'
          : 'Manually registered by the network team',
        evidence_json: '{}',
      });
      setNotice(`Added ${device.hostname || device.name} as asset #${created.id}. Collect evidence before treating its posture as current.`);
      setDevice({ name: '', kind: 'switch', hostname: '', owner: 'net-team', zone: 'core',
        criticality: 'high', status: 'operational', os_name: '' });
      setShowAdd(false);
      load();
    } catch (e: any) {
      setErr(String(e?.message ?? e));
    } finally {
      setAdding(false);
    }
  };

  const addRel = async () => {
    setErr('');
    try {
      await api.post('/api/relationships', { ...rel, source_id: Number(rel.source_id), target_id: Number(rel.target_id) });
      setRel({ source_type: 'asset', source_id: '', target_type: 'asset', target_id: '', rel: 'depends_on' });
      load();
    } catch (e: any) { setErr(String(e)); }
  };
  const delRel = async (id: number) => {
    try { await api.del(`/api/relationships/${id}`); load(); } catch (e: any) { setErr(String(e)); }
  };

  const nameOf = (type: string, id: any) => {
    if (type === 'service') {
      const s = services.find((x) => String(x.id) === String(id));
      return s ? s.name : `service ${id}`;
    }
    const a = assets.find((x) => String(x.id) === String(id));
    return a ? (a.hostname || a.name) : `asset ${id}`;
  };

  const networkCounts = useMemo(() => ({
    router: assets.filter((x) => x.kind === 'router').length,
    switch: assets.filter((x) => x.kind === 'switch').length,
    firewall: assets.filter((x) => x.kind === 'firewall').length,
  }), [assets]);

  if (err && nodes.length === 0) return <Page title="Infrastructure Map" crumb="CivicShield / Infrastructure / Map"><Err msg={err} /></Page>;
  return (
    <Page title="Infrastructure Map" crumb="CivicShield / Infrastructure / Map"
      actions={
        <>
          <span className="text-[11px] text-slate-500">{assets.length} assets · {edges.length} relationships</span>
          <button className="btn" onClick={() => setShowAdd((v) => !v)} aria-expanded={showAdd}>
            <Plus size={14} aria-hidden="true" /> {showAdd ? 'Close form' : 'Add device'}
          </button>
        </>
      }>
      {err && <Err msg={err} />}
      {notice && (
        <div className="rounded-lg border border-accent/30 bg-accent/[0.07] px-3 py-2 text-[12px] text-emerald-200">
          {notice}
        </div>
      )}
      {showAdd && (
        <div className="card grid gap-2">
          <div>
            <h2 className="text-[13px]">Add a device to the map</h2>
            <p className="mt-0.5 text-[11px] text-slate-500">
              Registers an asset in the inventory and draws it on the map. Use the relationship picker below to record its uplink or dependency.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <label className="grid gap-1 text-[11px] text-slate-500">Device name *
              <input className="input" value={device.name} onChange={(e) => setDevice({ ...device, name: e.target.value })} placeholder="Access Switch — Plant 2" />
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Kind
              <select className="input" value={device.kind} onChange={(e) => setDevice({ ...device, kind: e.target.value })}>
                {Object.keys(KIND_COLOR).map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Hostname
              <input className="input font-mono" value={device.hostname} onChange={(e) => setDevice({ ...device, hostname: e.target.value })} placeholder="sw-plant02" />
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Owner
              <input className="input" value={device.owner} onChange={(e) => setDevice({ ...device, owner: e.target.value })} placeholder="net-team" />
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Zone
              <select className="input" value={device.zone} onChange={(e) => setDevice({ ...device, zone: e.target.value })}>
                {ZONE_ORDER.map((z) => <option key={z} value={z}>{z}</option>)}
              </select>
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Criticality
              <select className="input" value={device.criticality} onChange={(e) => setDevice({ ...device, criticality: e.target.value })}>
                <option value="low">low</option><option value="moderate">moderate</option>
                <option value="high">high</option><option value="critical">critical</option>
              </select>
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Status
              <select className="input" value={device.status} onChange={(e) => setDevice({ ...device, status: e.target.value })}>
                <option value="operational">operational</option><option value="degraded">degraded</option><option value="recovering">recovering</option>
              </select>
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">OS / model
              <input className="input" value={device.os_name} onChange={(e) => setDevice({ ...device, os_name: e.target.value })} placeholder="Cisco IOS 15.2" />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button className="btn" onClick={addDevice} disabled={adding || !device.name.trim()}>
              {adding ? 'Adding…' : 'Add device'}
            </button>
            <button className="btn-sec" onClick={() => setShowAdd(false)} disabled={adding}>Cancel</button>
            <span className="text-[10px] text-slate-500">
              Requires operator or admin role. A new device starts with no evidence, so detection will report UNKNOWN until the collector runs.
            </span>
          </div>
        </div>
      )}

      <div className="card">
        <div className="grid gap-2 sm:grid-cols-3">
          <div className="flex items-center gap-2 rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
            <Router size={15} style={{ color: KIND_COLOR.router }} aria-hidden="true" />
            <div>
              <div className="kpi-label">Edge routers</div>
              <div className="font-display text-lg font-semibold tnum text-slate-100">{networkCounts.router}</div>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
            <Network size={15} style={{ color: KIND_COLOR.switch }} aria-hidden="true" />
            <div>
              <div className="kpi-label">Switches</div>
              <div className="font-display text-lg font-semibold tnum text-slate-100">{networkCounts.switch}</div>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
            <ShieldCheck size={15} style={{ color: KIND_COLOR.firewall }} aria-hidden="true" />
            <div>
              <div className="kpi-label">Firewalls</div>
              <div className="font-display text-lg font-semibold tnum text-slate-100">{networkCounts.firewall}</div>
            </div>
          </div>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
          {Object.entries(KIND_COLOR).map(([kind, color]) => (
            <span key={kind} className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm" style={{ background: color }} aria-hidden="true" />
              {kind}
            </span>
          ))}
        </div>
      </div>

      {loading ? <Loading msg="Loading graph" /> : (
        <div className="card rf-dark p-0 overflow-hidden" style={{ height: '62vh', minHeight: 380 }}>
          <ReactFlow nodes={nodes} edges={edges} fitView><Background color={LINE} gap={20} /><Controls /><MiniMap /></ReactFlow>
        </div>
      )}

      <div className="card grid gap-2">
        <h3 className="text-[11px] uppercase tracking-wide text-slate-500">Relationships (verified links only — hypothetical edges are not drawn)</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2">
          <select className="input" value={rel.source_type} onChange={(e) => setRel({ ...rel, source_type: e.target.value })} aria-label="Source type">
            <option value="asset">asset</option><option value="service">service</option>
          </select>
          <input className="input" placeholder="source id" value={rel.source_id} onChange={(e) => setRel({ ...rel, source_id: e.target.value })} aria-label="Source ID" />
          <select className="input" value={rel.target_type} onChange={(e) => setRel({ ...rel, target_type: e.target.value })} aria-label="Target type">
            <option value="asset">asset</option><option value="service">service</option>
          </select>
          <input className="input" placeholder="target id" value={rel.target_id} onChange={(e) => setRel({ ...rel, target_id: e.target.value })} aria-label="Target ID" />
          <input className="input" placeholder="relation" value={rel.rel} onChange={(e) => setRel({ ...rel, rel: e.target.value })} aria-label="Relation" />
          <button className="btn" onClick={addRel} disabled={!rel.source_id || !rel.target_id || !rel.rel}>Add link</button>
        </div>
        <div className="max-h-44 overflow-auto text-[12px] text-slate-400">
          {rels.map((r: any) => (
            <div key={r.id} className="flex items-center gap-2 py-0.5">
              <span>{nameOf(r.source_type, r.source_id)} <span style={{ color: REL_COLOR[r.rel] ?? '#34D399' }}>—{r.rel}→</span> {nameOf(r.target_type, r.target_id)}</span>
              <button className="ml-auto text-slate-500 hover:text-red-300" onClick={() => delRel(Number(r.id))}>Remove</button>
            </div>
          ))}
          {rels.length === 0 && <span className="text-slate-500">No relationships recorded.</span>}
        </div>
      </div>
    </Page>
  );
}
