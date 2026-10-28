import { useEffect, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page } from '../components/ui';

export default function Threats() {
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [identity, setIdentity] = useState<any>(null);
  const [form, setForm] = useState({ value: '', kind: 'domain', confidence: 'medium', source: '' });
  const load = () => {
    api.get('/api/threat-indicators').then((d: any) => setItems(d.items ?? d ?? [])).catch((e) => setErr(String(e))).finally(() => setLoading(false));
    api.get('/api/identity').then(setIdentity).catch(() => {});
  };
  useEffect(() => { load(); }, []);
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
