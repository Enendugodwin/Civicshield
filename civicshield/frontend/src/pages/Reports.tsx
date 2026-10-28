import { useEffect, useState } from 'react';
import { ClipboardCheck, Download, RefreshCcw, ShieldAlert } from 'lucide-react';
import { api } from '../api';
import { Badge, Err, Loading, Page, download } from '../components/ui';

export default function Reports() {
  const [err, setErr] = useState('');
  const [review, setReview] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [focus, setFocus] = useState('all');
  const [audience, setAudience] = useState('technical');
  const [note, setNote] = useState('');

  const loadReview = async (nextFocus = focus, nextAudience = audience) => {
    setErr(''); setBusy(true);
    try {
      setReview(await api.get(`/api/review/posture?focus=${encodeURIComponent(nextFocus)}&audience=${encodeURIComponent(nextAudience)}`));
    } catch (e: any) { setErr(String(e?.message ?? e)); }
    finally { setBusy(false); setLoading(false); }
  };
  useEffect(() => { loadReview(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const dl = async (path: string, filename: string) => {
    setErr('');
    try { await download(path, filename); } catch (e: any) { setErr(String(e)); }
  };
  const copy = async () => {
    if (!review?.markdown) return;
    try { await navigator.clipboard.writeText(review.markdown); setNote('Review copied to clipboard.'); }
    catch { setNote('Clipboard unavailable; open the full review below.'); }
  };

  return (
    <Page title="Reports" crumb="CivicShield / Program / Reports"
      actions={<span className="text-[11px] text-slate-500">Exports reflect live backend records</span>}>
      {err && <Err msg={err} />}
      {note && <p role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.07] px-3 py-2 text-[12px] text-emerald-200">{note}</p>}

      <div className="card">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <ShieldAlert size={15} className="text-accent-soft" aria-hidden="true" />
          <h2 className="text-[13px]">Evidence-grounded security review</h2>
          <span className="text-[10px] text-slate-500">used by the MCP review tool</span>
          <div className="ml-auto flex flex-wrap gap-1.5">
            <select aria-label="Review focus" className="input w-auto py-1 text-[11px]" value={focus}
              onChange={(e) => { setFocus(e.target.value); loadReview(e.target.value, audience); }}>
              <option value="all">All findings</option>
              <option value="vulnerability">Known vulnerabilities</option>
              <option value="identity">Identity & access</option>
              <option value="backup">Backup & recovery</option>
              <option value="network">Network devices</option>
            </select>
            <select aria-label="Review audience" className="input w-auto py-1 text-[11px]" value={audience}
              onChange={(e) => { setAudience(e.target.value); loadReview(focus, e.target.value); }}>
              <option value="technical">Technical</option>
              <option value="executive">Executive</option>
            </select>
            <button className="btn-sec" onClick={() => loadReview()} disabled={busy}>
              <RefreshCcw size={12} aria-hidden="true" /> {busy ? 'Building…' : 'Refresh'}
            </button>
            <button className="btn-sec" onClick={copy} disabled={!review}>
              <ClipboardCheck size={12} aria-hidden="true" /> Copy markdown
            </button>
          </div>
        </div>
        {loading ? <Loading msg="Building evidence review" /> : review && (
          <>
            <div className="grid gap-2 sm:grid-cols-4">
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Open findings</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">{review.open_findings}</div>
                <div className="text-[10px] text-slate-500">{review.critical_high_findings} critical/high</div>
              </div>
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Known vulnerabilities</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-rose-300">{review.known_vulnerabilities}</div>
                <div className="text-[10px] text-slate-500">{review.critical_vulnerabilities} critical</div>
              </div>
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Services ready</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">{review.services_ready}</div>
                <div className="text-[10px] text-slate-500">procedure · backup · RTO</div>
              </div>
              <div className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                <div className="kpi-label">Evidence current</div>
                <div className="mt-0.5 font-display text-lg font-semibold tnum text-slate-100">{review.evidence_current}</div>
                <div className="text-[10px] text-slate-500">{review.assets} active assets</div>
              </div>
            </div>

            <div className="mt-3 grid gap-3 lg:grid-cols-[1.2fr_1fr]">
              <div>
                <h3 className="mb-1 text-[11px] uppercase tracking-wide text-slate-500">Priority findings</h3>
                <div className="tblwrap">
                  <table className="tbl min-w-[460px]">
                    <thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>Source</th></tr></thead>
                    <tbody>
                      {(review.top_findings ?? []).slice(0, 8).map((f: any) => (
                        <tr key={`${f.rule_id}-${f.asset_id}`}>
                          <td className="whitespace-nowrap font-mono text-[11px] text-slate-200">{f.rule_id}</td>
                          <td className="max-w-[10rem] truncate text-slate-400">{f.asset_name ?? f.asset_id}</td>
                          <td><Badge text={String(f.severity)} /></td>
                          <td><Badge text={f.source === 'vulnerability' ? 'CVE' : 'Config'} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {(review.top_findings ?? []).length === 0 && <p className="py-3 text-center text-[12px] text-slate-500">No findings match this focus.</p>}
                </div>
              </div>
              <div>
                <h3 className="mb-1 text-[11px] uppercase tracking-wide text-slate-500">Recommended next actions</h3>
                <ol className="grid gap-1.5 text-[11.5px] leading-relaxed text-slate-300">
                  {(review.recommendations ?? []).map((r: string, i: number) => (
                    <li key={i} className="flex gap-2">
                      <span className="font-mono text-[10px] text-accent-soft">{i + 1}</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>

            <details className="mt-3">
              <summary className="cursor-pointer text-[11px] text-slate-400">Full markdown review</summary>
              <pre className="mt-2 max-h-[26rem] overflow-auto whitespace-pre-wrap rounded-md border border-line/70 bg-black/30 p-3 font-mono text-[10.5px] leading-relaxed text-slate-300">{review.markdown}</pre>
            </details>
            <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
              {review.limitations} No production changes are made by this review.
            </p>
          </>
        )}
      </div>

      <div className="grid gap-2">
        <div className="card flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-100">Executive posture</span>
          <span className="text-[12px] text-slate-500">top risks, readiness, provenance metadata, JSON</span>
          <span className="ml-auto flex gap-2">
            <button className="btn-sec" onClick={() => dl('/api/reports/posture', 'posture-report.json')}>JSON</button>
          </span>
        </div>
        <div className="card flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-100">Assessment results</span>
          <span className="text-[12px] text-slate-500">all runs, CSV</span>
          <span className="ml-auto flex gap-2">
            <button className="btn-sec" onClick={() => dl('/api/reports/assessment', 'assessment-report.csv')}>CSV</button>
          </span>
        </div>
        <div className="card flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-100">Recovery runs</span>
          <span className="text-[12px] text-slate-500">scenarios and metrics, JSON</span>
          <span className="ml-auto flex gap-2">
            <button className="btn-sec" onClick={() => dl('/api/reports/recovery', 'recovery-report.json')}>JSON</button>
          </span>
        </div>
        <div className="card flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-100">Threat exposure</span>
          <span className="text-[12px] text-slate-500">advisories vs assets, JSON + CSV</span>
          <span className="ml-auto flex gap-2">
            <button className="btn-sec" onClick={() => dl('/api/reports/threats', 'threats-report.json')}>JSON</button>
            <button className="btn-sec" onClick={() => dl('/api/reports/threats?format=csv', 'threats-report.csv')}>CSV</button>
          </span>
        </div>
        <div className="card flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-100">Audit log</span>
          <span className="text-[12px] text-slate-500">security-relevant changes, JSON</span>
          <span className="ml-auto flex gap-2">
            <button className="btn-sec" onClick={() => dl('/api/audit', 'audit-log.json')}>JSON</button>
          </span>
        </div>
      </div>
      <div className="flex justify-end">
        <button className="btn-sec" onClick={() => dl('/api/reports/posture', 'posture-report.json')}>
          <Download size={12} aria-hidden="true" /> Download posture
        </button>
      </div>
    </Page>
  );
}
