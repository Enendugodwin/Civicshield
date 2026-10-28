import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

export default function Threats() {
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [identity, setIdentity] = useState<any>(null);
  const [exposure, setExposure] = useState<any>(null);
  const [sync, setSync] = useState<any>(null);
  const [analyses, setAnalyses] = useState<Record<string, any>>({});
  const [analyzing, setAnalyzing] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('all');
  const [kevOnly, setKevOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [form, setForm] = useState({ value: '', kind: 'domain', confidence: 'medium', source: '' });
  const load = () => {
    api.get('/api/threat-indicators').then((d: any) => setItems(d.items ?? d ?? [])).catch((e) => setErr(String(e))).finally(() => setLoading(false));
    api.get('/api/identity').then(setIdentity).catch(() => {});
    api.get('/api/threats/exposure').then(setExposure).catch(() => {});
    api.get('/api/threats/sync-status').then(setSync).catch(() => {});
  };
  useEffect(() => { load(); }, []);
  const analyze = async (advisoryId: string) => {
    if (analyzing) return;
    setErr(''); setAnalyzing(advisoryId);
    try {
      const d = await api.post('/api/threats/analysis', { advisory_id: advisoryId });
      setAnalyses((m) => ({ ...m, [advisoryId]: d }));
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setAnalyzing(null); }
  };
  const syncNow = async () => {
    if (syncing) return;
    setErr(''); setSyncing(true);
    try {
      const d = await api.post('/api/threats/sync', {});
      setSync((s: any) => ({ ...(s ?? {}), last_sync: d, never_synced: false }));
      if (!d.ok) setErr(`Feed sync incomplete: ${(d.warnings ?? []).join('; ') || 'provider unreachable'}. Bundled advisories still apply.`);
    } catch (e: any) { setErr(String(e?.message ?? e)); } finally { setSyncing(false); }
  };
  const advisories = (exposure?.advisories ?? []).filter((a: any) => {
    if (sev !== 'all' && String(a.severity).toLowerCase() !== sev) return false;
    if (kevOnly && !a.known_exploited) return false;
    if (q && !`${a.id} ${a.title}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });
  const dash = (exposure?.advisories ?? []).reduce((d: any, a: any) => {
    const s = String(a.severity).toLowerCase();
    if (s === 'critical' || s === 'high') d.critHigh += 1;
    if (a.known_exploited && (a.confirmed.length + a.potential.length) > 0) d.kevRelevant += 1;
    d.confirmedAssets += a.confirmed.length; d.potentialAssets += a.potential.length;
    return d;
  }, { critHigh: 0, kevRelevant: 0, confirmedAssets: 0, potentialAssets: 0 });
  const add = async () => {
    setErr('');
    try { await api.post('/api/threat-indicators', form); setForm({ value: '', kind: 'domain', confidence: 'medium', source: '' }); load(); }
    catch (e: any) { setErr(String(e)); }
  };
  return (
    <Page title="Threat Intelligence" crumb="CivicShield / Resilience / Threat Intelligence"
      actions={<span className="text-[11px] text-slate-500">{items.length} indicators · unverified submissions never auto-block</span>}>
      {err && <Err msg={err} />}
      {identity && (
        <div className="card">
          <h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Identity security — privileged accounts (from asset evidence)</h3>
          <div className="text-[12px] text-slate-300 mb-2">
            MFA coverage: <b>{identity.mfa_coverage === null ? 'unknown (no MFA evidence recorded)' : `${Math.round(identity.mfa_coverage * 100)}% of ${identity.accounts.length} accounts`}</b>
            {identity.mfa_unknown > 0 && <span className="text-slate-500"> · {identity.mfa_unknown} with unknown MFA status (treated as unknown, not disabled)</span>}
          </div>
          <div className="tblwrap overflow-x-auto max-h-56"><table className="tbl min-w-[480px]">
            <thead><tr><th>Asset</th><th>Account</th><th>MFA</th></tr></thead>
            <tbody>{identity.accounts.map((a: any, i: number) => (
              <tr key={i}><td className="text-slate-100">{a.asset}</td><td className="text-slate-400">{a.account}</td>
                <td><Badge text={a.mfa} /></td></tr>
            ))}</tbody>
          </table></div>
          <div className="text-[11px] text-slate-500 mt-1">Access changes are simulated and recorded with approvals — live accounts are never modified.</div>
        </div>
      )}
      {exposure && (
        <div className="card">
          <h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">
            Threat dashboard — bundled catalog ({exposure.snapshot}) vs declared asset software
          </h3>
          <div className="grid gap-1.5 sm:grid-cols-4">
            {[
              ['Critical / high', dash.critHigh],
              ['KEV affecting environment', dash.kevRelevant],
              ['Confirmed assets', dash.confirmedAssets],
              ['Potential assets', dash.potentialAssets],
            ].map(([k, v]: any) => (
              <div key={k} className="rounded-md border border-line/70 bg-raised/30 px-2 py-1.5">
                <div className="text-[9.5px] uppercase tracking-[0.06em] text-slate-500">{k}</div>
                <div className="mt-0.5 font-display text-[15px] font-semibold tnum text-slate-100">{v}</div>
              </div>
            ))}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
            <span>
              Feed health: {sync?.never_synced ?? true
                ? 'no live sync yet — bundled advisories only'
                : sync?.last_sync?.ok
                  ? `synced ${new Date((sync.last_sync.finished_at ?? 0) * 1000).toLocaleString()} · ${sync.last_sync.osv_findings ?? 0} OSV findings`
                  : `last sync incomplete (${(sync?.last_sync?.warnings ?? []).slice(0, 1).join('; ') || 'provider unreachable'}) — bundled advisories still apply`}
              {typeof sync?.osv_cache_entries === 'number' && ` · OSV cache: ${sync.osv_cache_entries} entries`}
            </span>
            <button className="btn-sec ml-auto" onClick={syncNow} disabled={syncing}>
              {syncing ? 'Syncing…' : 'Sync now'}
            </button>
          </div>
          <div className="mt-2 flex flex-wrap items-end gap-2">
            <label className="grid min-w-0 flex-1 gap-1 text-[11px] text-slate-500">Search
              <input className="input py-1" value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE ID or title" aria-label="Search advisories" />
            </label>
            <label className="grid gap-1 text-[11px] text-slate-500">Severity
              <select className="input w-auto py-1" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Filter by severity">
                <option value="all">All</option><option value="critical">Critical</option>
                <option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
              </select>
            </label>
            <label className="flex items-center gap-1.5 pb-1.5 text-[11px] text-slate-400">
              <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
              Known exploited only
            </label>
          </div>
          <div className="mt-2 grid gap-2">
            {advisories.length === 0 && <p className="py-2 text-center text-[12px] text-slate-500">No advisories match these filters.</p>}
            {advisories.map((a: any) => {
              const analysis = analyses[a.id];
              const open = expanded === a.id;
              return (
                <div key={a.id} className="rounded-md border border-line/70 bg-raised/30 px-2 py-1.5">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <button className="font-mono text-[11.5px] text-accent-soft hover:underline"
                      onClick={() => setExpanded(open ? null : a.id)}
                      aria-expanded={open} aria-label={`${open ? 'Collapse' : 'Expand'} ${a.id} details`}>
                      {a.id}
                    </button>
                    <Badge text={String(a.severity)} />
                    {a.known_exploited && <Badge text="known exploited" />}
                    <span className="text-[12px] text-slate-300">{a.title}</span>
                    <span className="ml-auto text-[11px] text-slate-500">
                      {a.confirmed.length} confirmed · {a.potential.length} potential
                    </span>
                  </div>
                  {open && (
                    <div className="mt-1.5 border-t border-line/70 pt-1.5 text-[11.5px]">
                      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-slate-400">
                        <span>CVSS: <b className="text-slate-200">{a.cvss ?? 'n/a'}</b></span>
                        <span>Fixed in: <b className="text-slate-200">{a.fixed}</b></span>
                        <a className="text-accent-soft hover:underline" href={a.url} target="_blank" rel="noreferrer">Vendor advisory ↗</a>
                      </div>
                      <p className="mt-1 text-slate-500">{a.limitation}</p>
                      {a.confirmed.concat(a.potential).length > 0 ? (
                        <ul className="mt-1 grid gap-0.5">
                          {a.confirmed.concat(a.potential).map((m: any) => (
                            <li key={`${m.asset_id}-${m.package}`} className="text-slate-300">
                              <Link className="text-accent-soft hover:underline" to="/assets">{m.asset_name}</Link>
                              <span className="text-slate-500"> · {m.package}@{m.version} · {m.asset_id && a.confirmed.includes(m) ? 'confirmed' : 'potential'}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="mt-1 text-slate-500">No asset declares the affected product. {a.unevaluated.length} asset(s) have no software inventory — scope unconfirmed there.</p>
                      )}
                      <p className="mt-1 text-slate-400">
                        <span className="text-slate-500">Recommended action (rules-based): </span>{a.recommended_action}
                      </p>
                      <button className="btn-sec mt-1.5" disabled={analyzing === a.id}
                        onClick={() => analyze(a.id)}>
                        {analyzing === a.id ? 'Analyzing…' : analysis ? 'Re-analyze' : 'Generate AI analysis'}
                      </button>
                      {analysis && (
                        <div className="mt-1.5 border-t border-line/70 pt-1.5">
                          <div className="flex flex-wrap items-baseline gap-2">
                            <span className="text-[11.5px] font-medium text-slate-200">AI analysis</span>
                            <span className="font-mono text-[10px] text-slate-500">model: {analysis.model_used}</span>
                            <Link to="/remediation" className="ml-auto text-[11px] text-accent-soft hover:underline">
                              Open plan {analysis.plan_id} in Remediation
                            </Link>
                          </div>
                          <p className="mt-0.5 text-[12px] text-slate-300">{analysis.plan?.plain_language}</p>
                          <p className="mt-0.5 text-slate-400">{analysis.plan?.corrective_action}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      <div className="card grid sm:grid-cols-2 lg:grid-cols-5 gap-2">
        <label className="grid gap-1 text-[11px] text-slate-500">Value<input className="input" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder="malicious.example" /></label>
        <label className="grid gap-1 text-[11px] text-slate-500">Kind
          <select className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
            <option value="domain">domain</option><option value="url">url</option><option value="hash">hash</option><option value="campaign">campaign</option>
          </select></label>
        <label className="grid gap-1 text-[11px] text-slate-500">Confidence
          <select className="input" value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })}>
            <option value="low">low</option><option value="medium">medium</option><option value="high">high</option>
          </select></label>
        <label className="grid gap-1 text-[11px] text-slate-500">Source<input className="input" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} placeholder="reference" /></label>
        <div className="flex items-end"><button className="btn w-full" onClick={add} disabled={!form.value}>Add indicator</button></div>
      </div>
      {loading ? <Loading msg="Loading indicators" /> : items.length === 0 ? <Empty msg="No indicators yet." /> : (
        <div className="tblwrap p-2 overflow-x-auto"><table className="tbl min-w-[720px]">
          <thead><tr><th>Indicator</th><th>Kind</th><th>Confidence</th><th>Source</th><th>Expires</th><th>State</th></tr></thead>
          <tbody>{items.map((x: any, i: number) => (
            <tr key={x.value ?? i}><td className="text-slate-100 font-mono text-[12px]">{x.value ?? x.indicator}</td>
              <td className="text-slate-400">{x.kind ?? x.type}</td>
              <td><Badge text={String(x.confidence ?? 'unknown')} /></td>
              <td className="max-w-[16rem] truncate text-slate-400" title={x.source}>{x.source || '—'}</td>
              <td className="text-[11px] text-slate-500">{x.expires_at ? new Date(x.expires_at * 1000).toLocaleDateString() : '—'}</td>
              <td>{x.expired ? <Badge text="expired" /> : <Badge text="active" />}</td></tr>
          ))}</tbody>
        </table></div>
      )}
    </Page>
  );
}
