import { useEffect, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Err, Loading, Page, download } from '../components/ui';

const KINDS = ['observed', 'evidence', 'interpretation', 'suggestion', 'decision'];

export default function Incidents() {
  const [items, setItems] = useState<any[]>([]);
  const [title, setTitle] = useState('');
  const [sev, setSev] = useState('medium');
  const [commander, setCommander] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [sel, setSel] = useState<number | null>(null);
  const [detail, setDetail] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [summary, setSummary] = useState<any>(null);
  const [summarizing, setSummarizing] = useState(false);
  const [evKind, setEvKind] = useState('observed');
  const [evText, setEvText] = useState('');
  const [linkFid, setLinkFid] = useState('');
  const [done, setDone] = useState<Record<string, boolean>>({});

  const load = () => {
    api.get('/api/incidents').then((d: any) => setItems(d.items ?? d ?? [])).catch((e) => setErr(String(e))).finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);
  const open = async (id: number) => {
    setErr(''); setSel(id); setReport(null); setSummary(null); setDone({});
    try { setDetail(await api.get(`/api/incidents/${id}`)); }
    catch (e: any) { setErr(String(e)); }
  };
  const summarize = async () => {
    if (!sel) return;
    setErr(''); setSummarizing(true);
    try { setSummary(await api.post(`/api/incidents/${sel}/summary`, {})); }
    catch (e: any) { setErr(String(e)); } finally { setSummarizing(false); }
  };
  const create = async () => {
    try { await api.post('/api/incidents', { title, severity: sev, commander }); setTitle(''); setCommander(''); load(); } catch (e: any) { setErr(String(e)); }
  };
  const assignCommander = async () => {
    if (!sel || !commander) return;
    try { await api.patch(`/api/incidents/${sel}`, { commander }); setCommander(''); setDetail(await api.get(`/api/incidents/${sel}`)); load(); }
    catch (e: any) { setErr(String(e)); }
  };
  const addEvent = async () => {
    if (!sel || !evText) return;
    try {
      await api.post(`/api/incidents/${sel}/events`, { kind: evKind, detail: evText });
      setEvText(''); setDetail(await api.get(`/api/incidents/${sel}`));
    } catch (e: any) { setErr(String(e)); }
  };
  const link = async () => {
    if (!sel || !linkFid) return;
    try {
      await api.post(`/api/incidents/${sel}/findings/${linkFid}`, {});
      setLinkFid(''); setDetail(await api.get(`/api/incidents/${sel}`)); setReport(null);
    } catch (e: any) { setErr(String(e)); }
  };
  const unlink = async (fid: number) => {
    if (!sel) return;
    try {
      await api.del(`/api/incidents/${sel}/findings/${fid}`);
      setDetail(await api.get(`/api/incidents/${sel}`)); setReport(null);
    } catch (e: any) { setErr(String(e)); }
  };
  const setStatus = async (status: string) => {
    if (!sel) return;
    try {
      await api.patch(`/api/incidents/${sel}`, { status });
      setDetail(await api.get(`/api/incidents/${sel}`)); load();
    } catch (e: any) { setErr(String(e)); }
  };
  const showReport = async () => {
    if (!sel) return;
    try { setReport(await api.get(`/api/incidents/${sel}/report`)); }
    catch (e: any) { setErr(String(e)); }
  };

  return (
    <Page title="Incident Response" crumb="CivicShield / Resilience / Incidents"
      actions={<span className="text-[11px] text-slate-500">{items.length} incidents</span>}>
      {err && <Err msg={err} />}
      <div className="card grid sm:grid-cols-[1fr_140px_180px_auto] gap-2">
        <input className="input" placeholder="New incident title" value={title} onChange={(e) => setTitle(e.target.value)} aria-label="New incident title" />
        <select className="input" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity">
          <option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
        </select>
        <input className="input" placeholder="Commander (optional)" value={commander} onChange={(e) => setCommander(e.target.value)} aria-label="Commander" />
        <button className="btn" onClick={create} disabled={!title}>Create</button>
      </div>
      <div className="grid lg:grid-cols-[280px_1fr] gap-2 items-start">
        <div className="grid gap-2">
          {loading ? <Loading msg="Loading incidents" /> : items.length === 0 ? <Empty msg="No incidents recorded." /> : items.map((x: any) => (
            <button key={x.id} onClick={() => open(x.id)}
              className={`card text-left min-w-0 w-full ${sel === x.id ? '!border-emerald-400' : ''}`}>
              <div className="flex items-center gap-2 min-w-0"><span className="text-slate-500 text-[12px] shrink-0">#{x.id}</span>
                <span className="font-semibold text-slate-100 truncate min-w-0">{x.title}</span></div>
              <div className="mt-1 flex gap-1 flex-wrap"><Badge text={String(detail?.id === x.id ? detail.status : x.status)} />
                <Badge text={String(x.severity ?? 'medium')} />
                {(detail?.id === x.id ? detail.commander : x.commander) && <span className="text-[10px] text-slate-500">· {(detail?.id === x.id ? detail.commander : x.commander)}</span>}</div>
            </button>
          ))}
        </div>
        {!sel ? <Empty msg="Select an incident to work its timeline, evidence, findings, and containment." /> : !detail ? <Loading msg="Loading incident" /> : (
          <div className="grid gap-2">
            <div className="card flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-slate-100">#{detail.id} {detail.title}</span>
              <Badge text={String(detail.status)} />
              <Badge text={String(detail.severity ?? 'medium')} />
              <span className="text-[11px] text-slate-500">Commander: {detail.commander || 'unassigned'}</span>
              <span className="ml-auto flex gap-2 flex-wrap">
                {['open', 'contained', 'resolved'].map((s) => (
                  <button key={s} className="btn-sec" disabled={detail.status === s} onClick={() => setStatus(s)}>{s}</button>
                ))}
                <button className="btn-sec" onClick={showReport}>Report</button>
                <button className="btn-sec" onClick={summarize} disabled={summarizing}>{summarizing ? 'Summarizing…' : 'AI summary'}</button>
                <button className="btn-sec" onClick={() => download(`/api/incidents/${sel}/report`, `incident-${sel}.json`)}>Export</button>
              </span>
            </div>
            <div className="card flex flex-col sm:flex-row gap-2">
              <input className="input" placeholder="Assign commander" value={commander} onChange={(e) => setCommander(e.target.value)} aria-label="Assign commander" />
              <button className="btn-sec" onClick={assignCommander} disabled={!commander}>Assign</button>
            </div>
            <div className="card">
              <h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Timeline — observed vs interpreted vs suggested</h3>
              <div className="grid gap-1.5 max-h-[260px] overflow-auto">
                {detail.events.length === 0 && <div className="text-[12px] text-slate-500">No events yet. Record the first observation below.</div>}
                {detail.events.map((e: any) => (
                  <div key={e.id} className="flex gap-2 text-[12px] items-baseline flex-wrap min-w-0">
                    <Badge text={e.kind} />
                    <span className="text-slate-300 flex-1 min-w-0 break-words">{e.detail}</span>
                    <span className="text-slate-600 text-[11px] whitespace-nowrap">{new Date(e.ts * 1000).toLocaleString()}</span>
                  </div>
                ))}
              </div>
              <div className="flex flex-col sm:flex-row gap-2 mt-2">
                <select className="input sm:max-w-[160px]" value={evKind} onChange={(e) => setEvKind(e.target.value)} aria-label="Event kind">
                  {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
                </select>
                <input className="input" placeholder="Record event (facts only — no invented timestamps)" value={evText} onChange={(e) => setEvText(e.target.value)} aria-label="Event detail" />
                <button className="btn" onClick={addEvent} disabled={!evText}>Record</button>
              </div>
            </div>
            <div className="card">
              <h3 className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Linked findings ({detail.findings.length})</h3>
              {detail.findings.map((f: any) => (
                <div key={f.id} className="flex items-center gap-2 text-[12px] py-1 border-t border-line/60 flex-wrap min-w-0">
                  <Badge text={String(f.severity)} />
                  <span className="text-slate-200 break-words min-w-0">{f.rule_id}</span>
                  <span className="text-slate-500 whitespace-nowrap">asset {f.asset_id}</span>
                  <button className="ml-auto text-slate-500 hover:text-red-300 min-h-[44px] px-2" onClick={() => unlink(f.id)}>Unlink</button>
                </div>
              ))}
              <div className="flex flex-col sm:flex-row gap-2 mt-2">
                <input className="input" placeholder="Finding ID to link" value={linkFid} onChange={(e) => setLinkFid(e.target.value)} aria-label="Finding ID to link" />
                <button className="btn-sec" onClick={link} disabled={!linkFid}>Link finding</button>
              </div>
            </div>
            {summary && (
              <div className="card grid gap-2">
                <h3 className="text-[11px] uppercase tracking-wide text-slate-500">AI summary ({summary.model_used}) — grounded in recorded evidence</h3>
                <p className="text-[13px] text-slate-200">{summary.summary}</p>
                {summary.missing_evidence?.length > 0 && (
                  <div className="text-[12px] text-amber-300">Missing evidence: {summary.missing_evidence.join(' · ')}</div>
                )}
                <div className="text-[11px] text-slate-500">{summary.note}</div>
              </div>
            )}
            {report && (
              <div className="card grid gap-2">
                <h3 className="text-[11px] uppercase tracking-wide text-slate-500">Containment checklist (derived, requires human approval)</h3>
                {report.containment.length === 0 && <div className="text-[12px] text-slate-500">Link a finding to generate containment steps.</div>}
                {report.containment.map((s: string) => (
                  <label key={s} className="flex items-start gap-2 text-[13px] text-slate-200 cursor-pointer">
                    <input type="checkbox" className="mt-1" checked={!!done[s]} onChange={() => setDone((d) => ({ ...d, [s]: !d[s] }))} />
                    <span className={done[s] ? 'line-through text-slate-500' : ''}>{s}</span>
                  </label>
                ))}
                <div className="text-[11px] text-slate-500">{report.synthetic_note}</div>
                {report.decisions.length > 0 && (
                  <div className="text-[12px] text-slate-400">Recorded decisions: {report.decisions.join(' · ')}</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Page>
  );
}
