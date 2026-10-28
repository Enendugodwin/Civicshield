import { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ChevronDown, RefreshCw } from 'lucide-react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Line, LineChart, ResponsiveContainer } from 'recharts';
import { Asset, AssetStatus, Dataset, loadDataset, toCsv } from './data';
import { AssetDrawer, AssetTable, CustomerImpact, FilterBar, IncidentDrawer, MapTab, ServiceStatus, SloBurn, Timeline, WhatsDown } from './Components';
import { Page } from '../components/ui';

const STATUS_COLOR: Record<AssetStatus, string> = {
  Down: '#ef4444', Degraded: '#f59e0b', 'At Risk': '#eab308',
  Recovering: '#3b82f6', Operational: '#22c55e',
};

const TABS = ['What\'s Down', 'Critical Service Status', 'Assets Table', 'Affected Assets Intelligence Map', 'Customer Impact Map', 'SLO / SLA Burn Chart', 'Availability Timeline'];
const DEFAULT_TAB = 'Affected Assets Intelligence Map';

const LENSES: Record<string, { blurb: string; rank: (a: Asset) => number }> = {
  'SOC Analyst (L1/L2)': { blurb: 'Technical findings, evidence and affected hosts first.', rank: (a) => a.findings * 10 + (a.severity === 'Critical' ? 5 : 0) },
  'SOC Manager': { blurb: 'Workload and remediation progress across owners.', rank: (a) => (a.incidentId ? 10 : 0) + a.findings * 3 },
  'Incident Commander': { blurb: 'Service impact and restoration order.', rank: (a) => (a.status === 'Down' ? 20 : a.status === 'Degraded' ? 12 : 0) },
  'Exposure & Vulnerability': { blurb: 'Exposed assets and critical findings first.', rank: (a) => (a.severity === 'Critical' ? 15 : 0) + (a.status === 'At Risk' ? 8 : 0) },
  'Identity Security': { blurb: 'Identity-linked assets and MFA gaps first.', rank: (a) => (a.kind === 'directory' || a.name.includes('ws') ? 12 : 0) + a.findings * 2 },
  'AI Governance': { blurb: 'Model status and AI-assisted findings.', rank: (a) => a.findings },
  Executive: { blurb: 'Service health, risk and recovery readiness.', rank: (a) => (a.criticality === 'Critical' ? 10 : 0) + (a.status !== 'Operational' ? 8 : 0) },
  'Service Resilience': { blurb: 'Dependencies, backups and restoration objectives.', rank: (a) => (a.backupReady ? 0 : 6) + (a.status !== 'Operational' ? 6 : 0) },
};

export default function Dashboard() {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<Dataset | null>(null);
  const [error, setError] = useState('');
  const [lens, setLens] = useState('Executive');
  const [lensOpen, setLensOpen] = useState(false);
  const [fullMap, setFullMap] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [assetDrawer, setAssetDrawer] = useState<string | null>(null);
  const [incidentDrawer, setIncidentDrawer] = useState<string | null>(null);
  const [tileError, setTileError] = useState(false);
  const [filters, setFilters] = useState({ q: '', status: 'All', severity: 'All', owner: 'All', region: 'All', service: 'All' });
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 }>({ key: 'severity', dir: -1 });
  const mapRef = useRef<HTMLDivElement>(null);
  const leafletRef = useRef<{ map: L.Map; layer: L.LayerGroup } | null>(null);

  const rawTab = params.get('tab') ?? DEFAULT_TAB;
  const tab = TABS.includes(rawTab) ? rawTab : DEFAULT_TAB;
  const setTab = (t: string) => setParams((prev) => {
    const next = new URLSearchParams(prev);
    if (t === DEFAULT_TAB) next.delete('tab');
    else next.set('tab', t);
    return next;
  });

  useEffect(() => {
    const l = params.get('lens');
    if (l && LENSES[l]) setLens(l);
  }, []);
  useEffect(() => {
    loadDataset().then(setData).catch((e) => setError(String(e)));
  }, []);
  const refresh = () => {
    setError('');
    loadDataset().then(setData).catch((e) => setError(String(e)));
  };

  const filtered = useMemo(() => {
    if (!data) return [];
    const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 } as Record<string, number>;
    const rows = data.assets.filter((a) =>
      (!filters.q || (a.name + a.owner + a.service).toLowerCase().includes(filters.q.toLowerCase())) &&
      (filters.status === 'All' || a.status === filters.status) &&
      (filters.severity === 'All' || a.severity === filters.severity) &&
      (filters.owner === 'All' || a.owner === filters.owner) &&
      (filters.region === 'All' || a.region === filters.region) &&
      (filters.service === 'All' || a.service === filters.service));
    const val = (a: Asset): number | string => {
      if (sort.key === 'severity') return rank[a.severity] ?? 0;
      if (sort.key === 'status') return a.status;
      if (sort.key === 'name') return a.name;
      if (sort.key === 'region') return a.region;
      return a.name;
    };
    return [...rows].sort((x, y) => {
      const vx = val(x), vy = val(y);
      const c = typeof vx === 'number' ? vx - (vy as number) : String(vx).localeCompare(String(vy));
      return c * sort.dir;
    });
  }, [data, filters, sort]);

  const metrics = useMemo(() => {
    if (!data) return null;
    const down = data.services.filter((s) => s.status !== 'Operational').length;
    const affected = data.assets.filter((a) => a.status !== 'Operational').length;
    const crit = data.findings.length
      ? data.findings.filter((f) => ['critical', 'high'].includes(f.severity.toLowerCase())).length
      : data.assets.filter((a) => a.severity === 'Critical' || a.severity === 'High').length;
    const exposed = data.assets.filter((a) => a.kind === 'firewall' || a.status === 'At Risk').length;
    const ready = data.assets.filter((a) => a.backupReady).length;
    return { posture: affected === 0 ? 96 : Math.max(40, 96 - affected * 6), incidents: data.incidents.length || data.assets.filter((a) => a.incidentId).length, down, affected, exposed, crit, ready };
  }, [data]);

  // Leaflet map lifecycle
  useEffect(() => {
    if (!mapRef.current || leafletRef.current || !data) return;
    const map = L.map(mapRef.current, { zoomControl: false }).setView([7.51, 4.51], 11);
    L.control.zoom({ position: 'topright' }).addTo(map);
    const tiles = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18, attribution: '&copy; OpenStreetMap' });
    tiles.on('tileerror', () => setTileError(true));
    tiles.addTo(map);
    const layer = L.layerGroup().addTo(map);
    leafletRef.current = { map, layer };
    const fix = () => map.invalidateSize();
    const t = setTimeout(fix, 100);
    window.addEventListener('resize', fix);
    return () => { clearTimeout(t); window.removeEventListener('resize', fix); map.remove(); leafletRef.current = null; };
  }, [data, tab, fullMap]);

  useEffect(() => {
    const ref = leafletRef.current;
    if (!ref || !data) return;
    ref.layer.clearLayers();
    for (const a of filtered) {
      const m = L.marker([a.lat, a.lon], {
        icon: L.divIcon({
          className: '', html: `<div style="width:13px;height:13px;border-radius:50%;background:${STATUS_COLOR[a.status]};border:2px solid #0F172A;box-shadow:0 0 0 2px ${STATUS_COLOR[a.status]}55"></div>`,
          iconSize: [13, 13],
        }),
        title: a.name,
      });
      m.on('click', () => setSelected(a.id));
      if (a.id === selected) m.bindTooltip(a.name).openTooltip();
      m.addTo(ref.layer);
    }
  }, [filtered, selected, data]);

  if (error) {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/[0.07] p-4 text-[13px] text-red-200">
        <span>Dashboard failed to load: {error}</span>
        <button className="btn ml-auto" onClick={refresh}>Retry</button>
      </div>
    );
  }
  if (!data || !metrics) {
    return (
      <div className="grid gap-2" role="status" aria-label="Loading service health">
        <div className="skeleton h-8 w-1/2" />
        <div className="skeleton h-24 w-full" />
        <div className="skeleton h-64 w-full" />
      </div>
    );
  }
  const sel = data.assets.find((a) => a.id === selected) ?? null;
  const drawerAsset = data.assets.find((a) => a.id === assetDrawer) ?? null;
  const regions = [...new Set(data.assets.map((a) => a.region))];
  const owners = [...new Set(data.assets.map((a) => a.owner))];
  const queue = [...filtered].sort((x, y) => LENSES[lens].rank(y) - LENSES[lens].rank(x)).slice(0, 5);
  const exportCsv = () => {
    const blob = new Blob([toCsv(filtered)], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'affected-assets.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const connected = data.source === 'Connected';
  const statusMetrics: [string, string | number, string][] = [
    ['Posture', `${metrics.posture}%`, '#34D399'],
    ['Incidents', metrics.incidents, '#F59E0B'],
    ['Degraded', metrics.down, metrics.down ? '#F59E0B' : '#94A3B8'],
    ['Affected', metrics.affected, '#F59E0B'],
    ['Exposed', metrics.exposed, '#94A3B8'],
    ['Critical findings', metrics.crit, '#EF4444'],
    ['Recovery ready', `${metrics.ready}/${data.assets.length}`, '#34D399'],
  ];

  return (
    <div className="grid min-w-0 content-start gap-4">
      {/* Status strip */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 rounded-lg border border-line bg-rail/80 px-3 py-2">
        {statusMetrics.map(([label, value, color]) => (
          <div key={label} className="flex items-baseline gap-1.5 whitespace-nowrap">
            <span className="text-[10px] uppercase tracking-[0.07em] text-slate-500">{label}</span>
            <span className="font-mono text-[13px] font-semibold tnum" style={{ color }}>{value}</span>
          </div>
        ))}
        <div className="ml-auto flex items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 text-[10px] uppercase tracking-[0.07em] ${connected ? 'text-accent-soft' : 'text-amber-300'}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-accent-soft' : 'bg-amber-400'}`} aria-hidden="true" />
            {data.source}
          </span>
          <button className="btn-ghost" onClick={refresh}>
            <RefreshCw size={12} aria-hidden="true" /> Refresh
          </button>
        </div>
      </div>

      <Page
        title="Service Health"
        crumb={`CivicShield / Service Health / ${tab}`}
        actions={
          <div className="relative">
            <button
              className="btn-sec"
              onClick={() => setLensOpen(!lensOpen)}
              aria-haspopup="listbox"
              aria-expanded={lensOpen}
            >
              <span className="text-slate-500">Lens</span>
              <b className="font-medium text-accent-soft">{lens}</b>
              <ChevronDown size={13} aria-hidden="true" className={`text-slate-500 transition-transform ${lensOpen ? 'rotate-180' : ''}`} />
            </button>
            {lensOpen && (
              <div
                className="fade-in absolute right-0 z-30 mt-1 w-[calc(100vw-2rem)] max-w-[19rem] overflow-auto rounded-lg border border-line bg-surface p-1 shadow-float max-h-[70vh]"
                role="listbox"
                aria-label="Select analysis lens"
              >
                {Object.entries(LENSES).map(([name, v]) => (
                  <button
                    key={name}
                    role="option"
                    aria-selected={lens === name}
                    className={`w-full rounded-md px-2.5 py-2 text-left text-[12px] transition-colors hover:bg-white/[0.05] ${lens === name ? 'bg-accent/10' : ''}`}
                    onClick={() => { setLens(name); setLensOpen(false); }}
                  >
                    <div className={`font-semibold ${lens === name ? 'text-white' : 'text-slate-200'}`}>{name}</div>
                    <div className="mt-0.5 text-[11px] leading-snug text-slate-500">{v.blurb}</div>
                  </button>
                ))}
              </div>
            )}
          </div>
        }
      >
        <div className="flex flex-wrap items-baseline gap-2 font-mono text-[10.5px] text-slate-500">
          <span className="text-accent-soft">{lens}</span>
          <span aria-hidden="true">·</span>
          <span>{LENSES[lens].blurb}</span>
        </div>

        {/* Workspace tabs */}
        <nav
          className="-mt-1 flex gap-0.5 overflow-x-auto border-b border-line"
          aria-label="Service health views"
          role="tablist"
        >
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              aria-selected={tab === t}
              role="tab"
              className={`relative whitespace-nowrap px-2.5 pb-2 pt-2.5 text-[12px] transition-colors ${
                tab === t
                  ? 'font-semibold text-white after:absolute after:inset-x-1 after:-bottom-px after:h-0.5 after:rounded-full after:bg-accent-soft'
                  : 'text-slate-500 hover:text-slate-200'
              }`}
            >
              {t}
            </button>
          ))}
        </nav>

        {/* KPI cards */}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {(() => {
            const down = data.services.filter((s) => s.status !== 'Operational');
            const atRisk = data.services.filter((s) => s.status === 'Operational' && s.availability < s.slo + 0.5);
            return ([
              { label: 'Services down', value: down.length, color: '#EF4444', note: 'simulated count', spark: [1, 1, 2, 2] },
              { label: 'Affected assets', value: metrics.affected, color: '#F59E0B', note: 'click to isolate', spark: [2, 3, 3, metrics.affected], action: () => setFilters((f) => ({ ...f, status: f.status === 'All' ? 'Degraded' : 'All' })) },
              { label: 'SLAs at risk', value: down.length + atRisk.length, color: down.length ? '#EF4444' : '#22C55E', note: `of ${data.services.length} objectives`, spark: [0, 1, 1, 2] },
              { label: 'Avg recovery time', value: '3.5h', color: '#60A5FA', note: 'simulated estimate', spark: [4, 3.8, 3.5, 3.5] },
            ] as any[]).map((k) => {
              const inner = (
                <>
                  <div className="kpi-label">{k.label}</div>
                  <div className="flex items-end justify-between gap-2">
                    <span className="kpi-value" style={{ color: k.color }}>{k.value}</span>
                    <div className="h-[26px] w-[84px] shrink-0">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={k.spark.map((v: number, i: number) => ({ i, v }))}>
                          <Line type="monotone" dataKey="v" stroke={k.color} strokeWidth={1.5} dot={false} isAnimationActive={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="text-[10px] text-slate-500">{k.note}</div>
                </>
              );
              return k.action
                ? <button key={k.label} onClick={k.action} className="kpi text-left" title="Filter map and table">{inner}</button>
                : <div key={k.label} className="kpi">{inner}</div>;
            });
          })()}
        </div>

        <div className="min-h-0 min-w-0">
          {tab === 'Affected Assets Intelligence Map' && (
            <MapTab
              filtered={filtered} regions={regions} owners={owners} filters={filters} setFilters={setFilters}
              sort={sort} setSort={setSort} selected={selected} setSelected={setSelected}
              setAssetDrawer={setAssetDrawer} setIncidentDrawer={setIncidentDrawer}
              mapRef={mapRef} tileError={tileError} fullMap={fullMap} setFullMap={setFullMap}
              sel={sel} exportCsv={exportCsv} queue={queue} lens={lens} services={data.services}
            />
          )}
          {tab === "What's Down" && <WhatsDown data={data} setAssetDrawer={setAssetDrawer} />}
          {tab === 'Critical Service Status' && <ServiceStatus data={data} />}
          {tab === 'Assets Table' && (
            <div className="rounded-lg border border-line bg-surface p-2">
              <AssetTable rows={filtered} selected={selected} onSelect={setSelected} sort={sort} setSort={setSort}
                onAsset={setAssetDrawer} onIncident={setIncidentDrawer} exportCsv={exportCsv} compact={false} />
            </div>
          )}
          {tab === 'Customer Impact Map' && <CustomerImpact data={data} />}
          {tab === 'SLO / SLA Burn Chart' && <SloBurn data={data} />}
          {tab === 'Availability Timeline' && <Timeline data={data} />}
        </div>
      </Page>

      {/* Drawers */}
      {(drawerAsset || incidentDrawer) && (
        <div className="fixed inset-0 z-30 bg-black/65 backdrop-blur-[1px]" onClick={() => { setAssetDrawer(null); setIncidentDrawer(null); }} aria-hidden="true" />
      )}
      {drawerAsset && <AssetDrawer id={drawerAsset.id} data={data} onClose={() => setAssetDrawer(null)} />}
      {incidentDrawer && <IncidentDrawer id={incidentDrawer} data={data} onClose={() => setIncidentDrawer(null)} />}
    </div>
  );
}
