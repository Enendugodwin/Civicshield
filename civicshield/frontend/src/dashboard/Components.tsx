import { RefObject, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight, ChevronDown, ChevronUp, Download, Maximize2, Minimize2, Search, X,
} from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Asset, Dataset } from './data';
import { CHART } from '../components/ui';

const STATUS_COLOR: Record<string, string> = {
  Down: '#ef4444', Degraded: '#f59e0b', 'At Risk': '#eab308',
  Recovering: '#3b82f6', Operational: '#22c55e',
};
const SEV_COLOR: Record<string, string> = { Critical: '#ef4444', High: '#f59e0b', Medium: '#eab308', Low: '#22c55e' };

function Badge({ text, color }: { text: string; color: string }) {
  return <span className="badge" style={{ background: color + '1f', color, border: `1px solid ${color}4d` }}>{text}</span>;
}

export function FilterBar({ filters, setFilters, regions, owners, services }: any) {
  const set = (k: string, v: string) => setFilters((f: any) => ({ ...f, [k]: v }));
  const sel = 'bg-field border border-line rounded-md px-2 py-1 text-[11px] min-h-[34px] max-w-full text-slate-200';
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px]">
      <span className="relative min-w-[150px] flex-1 basis-40 sm:max-w-[13rem]">
        <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden="true" />
        <input
          className="min-h-[34px] w-full rounded-md border border-line bg-field py-1 pl-7 pr-2 text-[11px] text-slate-100 placeholder:text-slate-500"
          placeholder="Search assets…"
          value={filters.q}
          onChange={(e) => set('q', e.target.value)}
          aria-label="Search assets"
        />
      </span>
      {[['status', ['All', 'Down', 'Degraded', 'At Risk', 'Recovering', 'Operational']],
        ['severity', ['All', 'Critical', 'High', 'Medium', 'Low']],
        ['region', ['All', ...regions]], ['owner', ['All', ...owners]],
        ['service', ['All', ...services.map((s: any) => s.name)]]].map(([k, opts]: any) => (
        <select key={k} className={`${sel} min-w-[4.5rem] flex-1`} value={filters[k]} onChange={(e) => set(k, e.target.value)} aria-label={`${k} filter`}>
          {opts.map((o: string) => <option key={o}>{o}</option>)}
        </select>
      ))}
      <button
        className="min-h-[34px] shrink-0 rounded-md border border-line px-2 py-1 text-slate-400 transition-colors hover:border-slate-500 hover:text-white"
        onClick={() => setFilters({ q: '', status: 'All', severity: 'All', owner: 'All', region: 'All', service: 'All' })}
      >
        Reset
      </button>
    </div>
  );
}

export function AssetTable({ rows, selected, onSelect, sort, setSort, onAsset, onIncident, exportCsv, compact }: any) {
  const toggle = (key: string) => setSort({ key, dir: sort.key === key && sort.dir === -1 ? 1 : -1 });
  const th = (label: string, key: string) => {
    const active = sort.key === key;
    return (
      <th aria-sort={active ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
        <button type="button" className={`tbl-sort ${active ? 'text-slate-200' : ''}`} onClick={() => toggle(key)}>
          {label}
          {active
            ? (sort.dir === -1 ? <ChevronDown size={11} aria-hidden="true" /> : <ChevronUp size={11} aria-hidden="true" />)
            : <span className="w-[11px]" aria-hidden="true" />}
        </button>
      </th>
    );
  };
  return (
    <div>
      <div className="mb-1.5 flex items-center">
        <span className="text-[10.5px] uppercase tracking-[0.07em] text-slate-500">{rows.length} assets</span>
        <button className="btn-ghost ml-auto" onClick={exportCsv}><Download size={12} aria-hidden="true" /> CSV</button>
      </div>
      <div className="tblwrap" tabIndex={0} role="region" aria-label="Assets table, scroll horizontally on small screens">
        <table className={`w-full ${compact ? 'min-w-[420px]' : 'min-w-[560px]'} text-[11.5px]`}>
          <thead>
            <tr>{th('Asset', 'name')}{th('Region', 'region')}{th('Status', 'status')}{th('Severity', 'severity')}{!compact && <th>Service</th>}<th>Incident</th></tr>
          </thead>
          <tbody>
            {rows.map((a: Asset) => (
              <tr key={a.id} onClick={() => onSelect(a.id)} className={`cursor-pointer ${selected === a.id ? 'bg-accent/[0.08]' : ''}`}>
                <td className="py-1.5 pr-1"><button className="font-medium text-accent-soft hover:underline" onClick={(e) => { e.stopPropagation(); onAsset(a.id); }}>{a.name}</button></td>
                <td className="py-1.5 pr-1 text-slate-400">{a.region}</td>
                <td className="py-1.5 pr-1"><Badge text={a.status} color={STATUS_COLOR[a.status]} /></td>
                <td className="py-1.5 pr-1"><Badge text={a.severity} color={SEV_COLOR[a.severity]} /></td>
                {!compact && <td className="py-1.5 pr-1 text-slate-400">{a.service}</td>}
                <td className="py-1.5">{a.incidentId ? <button className="text-amber-300 hover:underline" onClick={(e) => { e.stopPropagation(); onIncident(a.incidentId); }}>{a.incidentId}</button> : <span className="text-slate-600">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && <div className="py-4 text-center text-[11px] text-slate-500">No assets match the current filters.</div>}
    </div>
  );
}

export function MapTab(props: any) {
  const { filtered, regions, owners, filters, setFilters, sort, setSort, selected, setSelected,
    setAssetDrawer, setIncidentDrawer, mapRef, tileError, fullMap, setFullMap, sel, exportCsv, queue, lens, services } = props;
  const affected = filtered.filter((a: Asset) => a.status !== 'Operational').length;
  return (
    <div className={`flex min-w-0 gap-2 ${fullMap ? '' : 'flex-col lg:flex-row'}`}>
      <div className={`${fullMap ? 'w-full' : 'lg:w-[62%]'} min-w-0 rounded-lg border border-line bg-surface p-2 flex flex-col`}>
        <div className="flex items-center gap-2 px-1 pb-1.5">
          <span className="font-display text-[12px] font-semibold text-white">Asset intelligence map</span>
          <span className="hidden text-[10px] text-slate-500 sm:inline">live markers · simulated positions</span>
          <button className="btn-ghost ml-auto shrink-0" onClick={() => { setFullMap(!fullMap); setTimeout(() => window.dispatchEvent(new Event('resize')), 150); }}>
            {fullMap ? <><Minimize2 size={12} aria-hidden="true" /> Exit full map</> : <><Maximize2 size={12} aria-hidden="true" /> Full map</>}
          </button>
        </div>
        <div className="mb-1.5 flex flex-wrap items-center gap-2">
          <FilterBar filters={filters} setFilters={setFilters} regions={regions} owners={owners} services={services} />
        </div>
        <div className="relative h-[46vh] min-h-[280px] overflow-hidden rounded-md border border-line sm:h-[52vh] lg:h-[540px]">
          <div ref={mapRef as RefObject<HTMLDivElement>} className="absolute inset-0 z-0" />
          {tileError && <div className="absolute left-2 top-2 z-10 max-w-[calc(100%-1rem)] rounded-md border border-amber-500/40 bg-amber-500/15 px-2 py-1 text-[10px] text-amber-300">Map tiles unavailable — showing schematic marker layout. Filters and selection still work.</div>}
          <div className="pointer-events-none absolute left-2 top-2 z-10 rounded-md border border-line bg-ink/90 px-2 py-1 font-mono text-[10px] text-slate-300 backdrop-blur-sm">
            Mapped: {filtered.length} · Down/Degraded: {affected} · Critical: {filtered.filter((a: Asset) => a.severity === 'Critical').length}
          </div>
          <div className="absolute bottom-2 left-2 z-10 max-w-[calc(100%-1rem)] rounded-md border border-line bg-ink/90 px-2 py-1 text-[10px] leading-relaxed text-slate-300 backdrop-blur-sm">
            {Object.entries(STATUS_COLOR).map(([k, c]) => <span key={k} className="mr-2 whitespace-nowrap"><span className="mr-1 inline-block h-2 w-2 rounded-full" style={{ background: c }} aria-hidden="true" />{k}</span>)}
          </div>
          {sel && (
            <div className="fade-in absolute bottom-2 right-2 z-10 w-60 max-w-[calc(100%-1rem)] rounded-lg border border-line bg-ink/95 p-2.5 text-[11px] shadow-float backdrop-blur">
              <div className="font-display text-[12px] font-semibold text-white">{sel.name}</div>
              <div className="text-slate-400">{sel.region} · {sel.service}</div>
              <div className="mt-1 flex gap-1"><Badge text={sel.status} color={STATUS_COLOR[sel.status]} /><Badge text={sel.severity} color={SEV_COLOR[sel.severity]} /></div>
              <div className="mt-1 text-slate-400">Findings: {sel.findings}{sel.incidentId ? ` · ${sel.incidentId}` : ''}</div>
              <button className="mt-1.5 inline-flex items-center gap-1 text-accent-soft hover:underline" onClick={() => setAssetDrawer(sel.id)}>View details <ArrowRight size={11} aria-hidden="true" /></button>
            </div>
          )}
        </div>
      </div>
      {!fullMap && (
        <div className="max-h-[60vh] min-w-0 overflow-auto rounded-lg border border-line bg-surface p-2 lg:max-h-[596px] lg:w-[38%]">
          <div className="flex items-center gap-2 px-1 pb-1.5">
            <span className="font-display text-[12px] font-semibold text-white">Affected assets</span>
            <span className="text-[10px] text-slate-500">synced with map</span>
          </div>
          <div className="mb-1 font-mono text-[10px] text-slate-500">Priority queue — {lens}</div>
          <ol className="mb-2 text-[11px]">
            {queue.map((a: Asset, i: number) => (
              <li key={a.id} className="flex items-center gap-1.5 py-0.5">
                <span className="w-4 font-mono text-slate-600">{i + 1}.</span>
                <button className="truncate text-left text-accent-soft hover:underline" onClick={() => setSelected(a.id)}>{a.name}</button>
                <span className="ml-auto shrink-0"><Badge text={a.severity} color={SEV_COLOR[a.severity]} /></span>
              </li>
            ))}
          </ol>
          <AssetTable rows={filtered} selected={selected} onSelect={setSelected} sort={sort} setSort={setSort}
            onAsset={setAssetDrawer} onIncident={setIncidentDrawer} exportCsv={exportCsv} compact />
        </div>
      )}
    </div>
  );
}

export function WhatsDown({ data, setAssetDrawer }: { data: Dataset; setAssetDrawer: (id: string) => void }) {
  const rows = data.assets.filter((a) => a.status === 'Down' || a.status === 'Degraded');
  return (
    <div className="rounded-lg border border-line bg-surface p-3 text-[12px]">
      <h2 className="mb-2">Unavailable and degraded — {rows.length} records</h2>
      {rows.map((a) => (
        <div key={a.id} className="flex min-w-0 flex-wrap items-center gap-2 border-b border-line/70 py-1.5">
          <Badge text={a.status} color={STATUS_COLOR[a.status]} />
          <button className="min-w-0 break-words font-semibold text-accent-soft hover:underline" onClick={() => setAssetDrawer(a.id)}>{a.name}</button>
          <span className="min-w-0 break-words text-slate-400">{a.service} · {a.region}</span>
          <span className="ml-auto"><Badge text={a.severity} color={SEV_COLOR[a.severity]} /></span>
        </div>
      ))}
      {rows.length === 0 && <div className="text-slate-500">No outages in the current dataset.</div>}
    </div>
  );
}

export function ServiceStatus({ data }: { data: Dataset }) {
  return (
    <div className="grid gap-2 md:grid-cols-3">
      {data.services.map((s) => (
        <div key={s.id} className="rounded-lg border border-line bg-surface p-3 text-[12px]">
          <div className="flex items-center gap-2"><span className="font-display font-semibold text-white">{s.name}</span><span className="ml-auto"><Badge text={s.status} color={STATUS_COLOR[s.status]} /></span></div>
          <div className="mt-2 text-slate-400">Availability <b className="font-mono tnum text-slate-100">{s.availability.toFixed(2)}%</b> · SLO <b className="font-mono tnum text-slate-100">{s.slo.toFixed(1)}%</b></div>
          <div className="mt-1 text-[11px] text-slate-500">Depends on: {s.dependsOn.join(', ') || '—'}</div>
          <div className="mt-1 text-[11px] text-slate-500">Beneficiaries (illustrative): {s.beneficiaries.toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

const tooltipStyle = { background: CHART.surface, border: `1px solid #26344D`, borderRadius: 8, fontSize: 11 };

export function CustomerImpact({ data }: { data: Dataset }) {
  // Once-per-service counting: each affected service's beneficiaries counted exactly
  // once and attributed to the region holding most of its affected assets.
  const byService = new Map<string, { regions: Map<string, number>; beneficiaries: number }>();
  for (const a of data.assets.filter((x) => x.status !== 'Operational')) {
    const svc = data.services.find((s) => s.name === a.service);
    if (!svc || byService.has(svc.name)) continue;
    byService.set(svc.name, { regions: new Map(), beneficiaries: svc.beneficiaries });
  }
  for (const a of data.assets.filter((x) => x.status !== 'Operational')) {
    const entry = byService.get(a.service);
    if (entry) entry.regions.set(a.region, (entry.regions.get(a.region) ?? 0) + 1);
  }
  const byRegion = new Map<string, number>();
  const byServiceRows: { service: string; region: string; beneficiaries: number }[] = [];
  for (const [name, entry] of byService) {
    const top = [...entry.regions.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] ?? 'unknown';
    byRegion.set(top, (byRegion.get(top) ?? 0) + entry.beneficiaries);
    byServiceRows.push({ service: name, region: top, beneficiaries: entry.beneficiaries });
  }
  const rows = [...byRegion.entries()];
  return (
    <div className="rounded-lg border border-line bg-surface p-3 text-[12px]">
      <h2 className="mb-1">Illustrative impact by region</h2>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={rows.map(([name, value]) => ({ name, value }))}>
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis dataKey="name" tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={{ stroke: CHART.grid }} tickLine={false} />
          <YAxis tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
          <Bar dataKey="value" fill={CHART.accent} radius={[3, 3, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
      <div className="tblwrap mt-2">
        <table className="tbl min-w-[420px]">
          <thead><tr><th>Service</th><th>Attributed region</th><th>Beneficiaries (counted once)</th></tr></thead>
          <tbody>{byServiceRows.map((r) => (
            <tr key={r.service}><td className="text-slate-100">{r.service}</td><td className="text-slate-400">{r.region}</td>
              <td className="tnum text-slate-200">{r.beneficiaries.toLocaleString()}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <div className="mt-1 text-[11px] text-slate-500">Each affected service's illustrative beneficiaries counted exactly once. Not measured telemetry.</div>
    </div>
  );
}

export function SloBurn({ data }: { data: Dataset }) {
  const days = Array.from({ length: 14 }, (_, i) => `D-${13 - i}`);
  const series = days.map((d, i) => ({
    d, water: 99.9 - (i > 9 ? (i - 9) * 0.35 : 0), billing: 99.95 - (i > 11 ? 0.4 : 0),
  }));
  return (
    <div className="rounded-lg border border-line bg-surface p-3 text-[12px]">
      <h2 className="mb-1">Availability vs SLO — trailing 14 days</h2>
      <ResponsiveContainer width="100%" height={240}>
        <LineChart data={series}>
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis dataKey="d" tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={{ stroke: CHART.grid }} tickLine={false} />
          <YAxis domain={[97, 100]} tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={tooltipStyle} />
          <Line type="monotone" dataKey="water" stroke={CHART.accent} strokeWidth={1.75} dot={false} name="Safe Water Delivery" isAnimationActive={false} />
          <Line type="monotone" dataKey="billing" stroke={CHART.warn} strokeWidth={1.75} dot={false} name="Billing Service" isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
      <div className="mt-1 text-[11px] text-slate-500">Burn rate = observed error ratio ÷ budgeted error ratio over the window. Synthetic series for illustration.</div>
    </div>
  );
}

export function Timeline({ data }: { data: Dataset }) {
  const items = [
    ...data.assets.filter((a) => a.status !== 'Operational').map((a) => ({ t: 'simulated', text: `${a.name} marked ${a.status} (${a.severity})`, sim: true })),
    ...data.incidents.map((i: any) => ({ t: 'recorded', text: `Incident #${i.id}: ${i.title} [${i.status}]`, sim: false })),
  ];
  return (
    <div className="rounded-lg border border-line bg-surface p-3 text-[12px]">
      <h2 className="mb-2">Availability timeline</h2>
      {items.map((e, i) => (
        <div key={i} className="flex min-w-0 gap-2 border-b border-line/70 py-1">
          <Badge text={e.sim ? 'simulated' : 'recorded'} color={e.sim ? '#eab308' : '#3b82f6'} />
          <span className="min-w-0 break-words text-slate-300">{e.text}</span>
        </div>
      ))}
      {items.length === 0 && <div className="text-slate-500">No events.</div>}
    </div>
  );
}

/** Shared dialog chrome: Escape closes, close button receives focus, backdrop is in the parent. */
function useDialog(onClose: () => void) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);
  return closeRef;
}

export function AssetDrawer({ id, data, onClose }: { id: string; data: Dataset; onClose: () => void }) {
  const closeRef = useDialog(onClose);
  const a = data.assets.find((x) => x.id === id);
  if (!a) return null;
  const findings = data.findings.filter((f) => String(f.asset_id) === id);
  return (
    <div className="drawer fixed inset-y-0 right-0 z-40 w-full max-w-md overflow-y-auto border-l border-line bg-rail pb-[max(1rem,env(safe-area-inset-bottom))] text-[12px] shadow-float" role="dialog" aria-modal="true" aria-label={`Asset ${a.name}`}>
      <div className="sticky top-0 z-10 flex items-start gap-2 border-b border-line bg-rail/95 px-4 py-3 backdrop-blur">
        <div className="min-w-0">
          <div className="section-label">Asset detail</div>
          <h2 className="break-words text-sm">{a.name}</h2>
        </div>
        <button ref={closeRef} className="ml-auto inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-white" onClick={onClose} aria-label="Close asset details">
          <X size={16} />
        </button>
      </div>
      <div className="grid gap-3 p-4">
        <div className="flex flex-wrap gap-1"><Badge text={a.status} color={STATUS_COLOR[a.status]} /><Badge text={a.severity} color={SEV_COLOR[a.severity]} /><Badge text={a.criticality} color="#60a5fa" /></div>
        <dl className="grid grid-cols-2 gap-x-3 gap-y-2">
          {[['Type', a.kind], ['Region', a.region], ['Owner', a.owner], ['Service', a.service],
            ['Backup ready', a.backupReady ? 'Yes (simulated)' : 'No record'], ['Incident', a.incidentId || '—']].map(([k, v]) => (
            <div key={k} className="min-w-0"><dt className="text-[10.5px] uppercase tracking-[0.06em] text-slate-500">{k}</dt><dd className="break-words text-slate-200">{v}</dd></div>
          ))}
        </dl>
        <div>
          <h3 className="mb-1 text-[10.5px] uppercase tracking-[0.07em] text-slate-500">Assessment results ({findings.length || a.findings})</h3>
          {findings.length === 0 && <div className="text-slate-500">Finding detail from the last assessment run will appear here. Open Findings & Risk for the full list.</div>}
          {findings.slice(0, 8).map((f) => (
            <div key={f.id} className="mb-1 rounded-md border border-line p-2">
              <div className="flex items-center gap-1"><Badge text={f.severity} color={SEV_COLOR[cap1(f.severity)] ?? '#94a3b8'} /><span className="font-mono text-[11px] text-slate-300">{f.rule_id}</span><span className="ml-auto font-mono text-[11px] text-slate-400">score {f.score}</span></div>
              <div className="mt-0.5 text-slate-400">{f.detail}</div>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          <Link className="btn" to="/findings">View findings</Link>
          <Link className="btn-sec" to="/recovery">Recovery status</Link>
          <Link className="btn-sec" to="/map">Dependency graph</Link>
        </div>
      </div>
    </div>
  );
}
function cap1(s: string) { return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase(); }

export function IncidentDrawer({ id, data, onClose }: { id: string; data: Dataset; onClose: () => void }) {
  const closeRef = useDialog(onClose);
  const num = Number(id.replace('INC-', '')) - 1000;
  const asset = data.assets.find((a) => a.id === String(num));
  const inc = data.incidents.find((i: any) => `INC-${1000 + i.id}` === id || String(i.id) === id);
  return (
    <div className="drawer fixed inset-y-0 right-0 z-40 w-full max-w-md overflow-y-auto border-l border-line bg-rail pb-[max(1rem,env(safe-area-inset-bottom))] text-[12px] shadow-float" role="dialog" aria-modal="true" aria-label={`Incident ${id}`}>
      <div className="sticky top-0 z-10 flex items-start gap-2 border-b border-line bg-rail/95 px-4 py-3 backdrop-blur">
        <div className="min-w-0">
          <div className="section-label">Incident</div>
          <h2 className="break-words text-sm">{id} <span className="font-sans text-[11px] font-normal text-slate-500">(simulated)</span></h2>
        </div>
        <button ref={closeRef} className="ml-auto inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-white" onClick={onClose} aria-label="Close incident details">
          <X size={16} />
        </button>
      </div>
      <div className="grid gap-3 p-4">
        <div className="text-slate-300">Status: {inc?.status ?? 'open (simulated)'} · Severity: {asset?.severity ?? '—'}</div>
        <div className="text-slate-300">Affected asset: {asset?.name ?? '—'} · Service: {asset?.service ?? '—'}</div>
        <div className="text-slate-500">Timeline and evidence come from recorded incident records. Synthetic demo content is labeled simulated; no timestamps are invented.</div>
        <div className="flex flex-wrap gap-2">
          <Link className="btn" to="/incidents">Open incident response</Link>
          {asset && <Link className="btn-sec" to="/recovery">Recovery status</Link>}
        </div>
      </div>
    </div>
  );
}
