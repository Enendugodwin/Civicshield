import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, CircleAlert, ClipboardCheck, DatabaseZap, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { Badge, CHART, Err, Loading, Page } from '../components/ui';

const PRIORITY_ORDER = ['Critical', 'High', 'Moderate', 'Low', 'Informational'];
const RANK: Record<string, number> = { critical: 5, high: 4, moderate: 3, medium: 3, low: 2, informational: 1 };
const DONE = new Set(['resolved', 'false_positive']);

function ago(ts?: number) {
  if (!ts) return 'never';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/** Real executive overview: only values derived from stored records. */
export default function Overview() {
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState('');
  const [ackBusy, setAckBusy] = useState<number | null>(null);
  const [ackErr, setAckErr] = useState('');

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const [a, f, as, inc, h, audit, readiness, posture, prot, notes] = await Promise.all([
          api.get('/api/assets').catch(() => []),
          api.get('/api/findings').catch(() => []),
          api.get('/api/assessments').catch(() => []),
          api.get('/api/incidents').catch(() => []),
          api.health().catch(() => ({})),
          api.get('/api/audit').catch(() => []),
          api.get('/api/recovery/readiness').catch(() => null),
          api.get('/api/detection/posture').catch(() => null),
          api.get('/api/protection/status').catch(() => null),
          api.get('/api/protection/notifications?unacked_only=true').catch(() => null),
        ]);
        const assets = a.items ?? a ?? [];
        const findings = f.items ?? f ?? [];
        const runs = as.items ?? as ?? [];
        const latest = runs[runs.length - 1];
        const results: any[] = latest
          ? await api.get(`/api/assessments/${latest.id}`).catch(() => [])
          : [];
        if (!live) return;
        setData({ assets, findings, runs, latest, results, inc, h, audit, readiness, posture, prot, notes: notes?.notifications ?? [] });
      } catch (e: any) {
        if (live) setErr(String(e?.message ?? e));
      }
    })();
    return () => { live = false; };
  }, []);

  const ack = async (id: number) => {
    if (ackBusy) return;
    setAckErr(''); setAckBusy(id);
    try {
      await api.post(`/api/protection/notifications/${id}/ack`, {});
      setData((d: any) => d && { ...d, notes: (d.notes ?? []).filter((n: any) => n.id !== id) });
    } catch (e: any) {
      setAckErr(String(e?.message ?? e));
    } finally {
      setAckBusy(null);
    }
  };

  const crumb = 'CivicShield / Overview';
  if (err) return <Page title="Overview" crumb={crumb}><Err msg={err} /></Page>;
  if (!data) return <Page title="Overview" crumb={crumb}><Loading msg="Loading live records" /></Page>;

  const { assets, findings, runs, latest, results, inc, h, audit, readiness, posture, prot, notes } = data;
  const incidents = inc.items ?? inc ?? [];
  const activity = (audit.items ?? audit ?? [])
    .filter((x: any) => !String(x.action).startsWith('assessment_run'))
    .slice(0, 6);

  const open = findings.filter((x: any) => !DONE.has(String(x.workflow ?? '')));
  const highOpen = open.filter((x: any) =>
    ['critical', 'high'].includes(String(x.priority ?? x.severity ?? '').toLowerCase()));
  const cves = open.filter((x: any) => String(x.rule_id).startsWith('CVE-'));
  const criticalCves = cves.filter((x: any) =>
    String(x.severity ?? '').toLowerCase() === 'critical');
  const activeIncidents = incidents.filter((x: any) => !['closed', 'resolved'].includes(String(x.status)));

  const counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, NA: 0 };
  results.forEach((r: any) => {
    const k = String(r.outcome);
    if (k in counts) (counts as any)[k] += 1;
  });
  const assessedAssets = new Set(results.map((r: any) => String(r.asset_id))).size;
  const unknownByAsset = new Map<string, number>();
  results.forEach((r: any) => {
    if (String(r.outcome) === 'UNKNOWN') {
      unknownByAsset.set(String(r.asset_id), (unknownByAsset.get(String(r.asset_id)) ?? 0) + 1);
    }
  });
  const gaps = [...unknownByAsset.entries()].sort((a, b) => b[1] - a[1]);
  const assetName = (id: string | number) => {
    const a = assets.find((x: any) => String(x.id) === String(id));
    return a ? a.name || a.hostname || `Asset ${id}` : `Asset ${id}`;
  };
  const services = readiness?.services ?? [];
  const ready = services.filter((s: any) => s.ready).length;

  const byPriority: Record<string, number> = {};
  open.forEach((x: any) => {
    const raw = String(x.priority ?? x.severity ?? 'unknown');
    const key = PRIORITY_ORDER.find((o) => o.toLowerCase() === raw.toLowerCase()) ?? raw;
    byPriority[key] = (byPriority[key] ?? 0) + 1;
  });

  const top = [...open]
    .sort((x: any, y: any) =>
      (RANK[String(y.priority ?? y.severity ?? '').toLowerCase()] ?? 0) - (RANK[String(x.priority ?? x.severity ?? '').toLowerCase()] ?? 0) ||
      (y.score ?? 0) - (x.score ?? 0))
    .slice(0, 5);

  const evidenceTotal = counts.PASS + counts.FAIL + counts.UNKNOWN;
  const outcomeRows = [
    { key: 'PASS', label: 'Passing controls', value: counts.PASS, color: '#34D399' },
    { key: 'FAIL', label: 'Failed checks', value: counts.FAIL, color: '#F87171' },
    { key: 'UNKNOWN', label: 'Unknown evidence', value: counts.UNKNOWN, color: '#FBBF24' },
  ];

  return (
    <Page
      title="Overview"
      crumb={crumb}
      actions={
        <span className="inline-flex items-center gap-1.5 text-[10.5px] uppercase tracking-[0.07em] text-slate-500">
          <span className={`h-1.5 w-1.5 rounded-full ${h?.ai?.available ? 'bg-accent-soft' : 'bg-amber-400'}`} aria-hidden="true" />
          AI {h?.ai?.available ? 'online' : 'fallback'}
        </span>
      }
    >
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-5">
        <div className="kpi">
          <div className="kpi-label">Assets in scope</div>
          <div className="kpi-value">{assets.length}</div>
          <div className="text-[10px] text-slate-500">
            {posture ? `${posture.assets_current}/${posture.assets_total} evidence current` : `${assessedAssets} covered by latest assessment`}
          </div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Critical &amp; high findings</div>
          <div className="kpi-value" style={{ color: highOpen.length ? '#F87171' : '#34D399' }}>{highOpen.length}</div>
          <div className="text-[10px] text-slate-500">{open.length} open in total</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Known vulnerabilities</div>
          <div className="kpi-value" style={{ color: cves.length ? '#F87171' : '#34D399' }}>{cves.length}</div>
          <div className="text-[10px] text-slate-500">{criticalCves.length} critical · version evidence</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Evidence gaps</div>
          <div className="kpi-value" style={{ color: gaps.length ? '#FBBF24' : '#34D399' }}>{gaps.length}</div>
          <div className="text-[10px] text-slate-500">
            {evidenceTotal ? `${counts.UNKNOWN} unknown of ${evidenceTotal} checks` : 'no assessment yet'}
          </div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Recovery readiness</div>
          <div className="kpi-value" style={{ color: services.length && ready === services.length ? '#34D399' : '#FBBF24' }}>
            {services.length ? `${ready}/${services.length}` : '—'}
          </div>
          <div className="text-[10px] text-slate-500">essential services meeting RTO criteria</div>
        </div>
      </div>

      {prot && (
        <div className="card">
          <div className="mb-2 flex flex-wrap items-baseline gap-2">
            <h2 className="text-[13px]">Continuous protection</h2>
            <Badge text={prot.enabled ? 'scheduled' : 'paused'} />
            {prot.last_run ? (
              <span className="font-mono text-[10px] text-slate-500">
                run #{prot.last_run.id} · {prot.last_run.trigger} · {prot.last_run.status} ·
                +{prot.last_run.opened}/~{prot.last_run.reopened}/-{prot.last_run.resolved} ·
                {ago(prot.last_run.finished_at || prot.last_run.started_at)}
              </span>
            ) : <span className="text-[11px] text-slate-500">No reassessment runs yet</span>}
            <span className="ml-auto text-[10px] text-slate-500">
              {prot.pending_events} queued · every {Math.round((prot.interval_seconds ?? 3600) / 60)} min ·
              {' '}{prot.unacked_notifications} unacknowledged
            </span>
          </div>
          {(notes ?? []).length === 0 ? (
            <p className="py-1 text-[12px] text-slate-500">
              Posture changes (new, changed, or cleared findings) appear here after each scheduled or
              event-driven reassessment. Nothing outstanding.
            </p>
          ) : (
            <ul className="grid gap-1.5">
              {(notes ?? []).slice(0, 5).map((n: any) => (
                <li key={n.id} className="flex items-center gap-2 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5">
                  <Badge text={String(n.kind).replace(/_/g, ' ')} />
                  <span className="min-w-0 flex-1 truncate text-[11.5px] text-slate-200" title={n.detail}>{n.title}</span>
                  <button className="btn-sec" disabled={ackBusy === n.id} onClick={() => ack(n.id)}>
                    {ackBusy === n.id ? 'Acking…' : 'Acknowledge'}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {ackErr && <p role="alert" className="mt-1 text-[11px] text-rose-300">{ackErr}</p>}
          <p className="mt-2 text-[10.5px] text-slate-500">
            Estate changes (imports, topology edits, evidence) queue an event reassessment; a scheduler
            also re-runs detection on an interval. Acknowledge notices explicitly — they never auto-clear.
          </p>
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-[1.25fr_1fr]">
        <div className="card">
          <div className="mb-2 flex flex-wrap items-baseline gap-2">
            <h2 className="text-[13px]">Assessment outcomes</h2>
            {latest ? (
              <>
                <Badge text={String(latest.status)} />
                <span className="font-mono text-[10px] text-slate-500">run #{latest.id} · rules {latest.rule_version} · {ago(latest.started_at)}</span>
              </>
            ) : <span className="text-[11px] text-slate-500">No run yet</span>}
            <Link to="/assessments" className="ml-auto inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
              Open assessments <ArrowRight size={12} aria-hidden="true" />
            </Link>
          </div>
          {evidenceTotal === 0 ? (
            <div className="py-6 text-center text-[12px] text-slate-500">
              Run an assessment to replace assumptions with recorded evidence.
            </div>
          ) : (
            <div className="grid gap-3">
              <div className="flex h-2 overflow-hidden rounded-full bg-white/[0.06]" role="img"
                aria-label={outcomeRows.map((r) => `${r.label}: ${r.value}`).join(', ')}>
                {outcomeRows.map((r) => r.value > 0 && (
                  <span key={r.key} style={{ width: `${(r.value / evidenceTotal) * 100}%`, background: r.color }} />
                ))}
              </div>
              <div className="grid gap-2 sm:grid-cols-3">
                {outcomeRows.map((r) => (
                  <div key={r.key} className="rounded-md border border-line/70 bg-raised/40 px-2.5 py-2">
                    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.07em] text-slate-500">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: r.color }} aria-hidden="true" />
                      {r.label}
                    </div>
                    <div className="mt-1 font-display text-lg font-semibold tnum text-slate-100">{r.value}</div>
                  </div>
                ))}
              </div>
              <p className="text-[11px] leading-relaxed text-slate-500">
                A control is <span className="text-rose-300">failed</span> only when recorded evidence contradicts it.
                Missing evidence is reported as <span className="text-amber-300">unknown</span>, never assumed secure.
              </p>
            </div>
          )}
        </div>

        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">Assets missing evidence</h2>
            <span className="ml-auto text-[10px] text-slate-500">{gaps.length} assets</span>
          </div>
          <div className="grid gap-2">
            {gaps.slice(0, 5).map(([id, n]) => (
              <div key={id} className="grid gap-1">
                <div className="flex items-baseline justify-between gap-2 text-[11px]">
                  <span className="truncate text-slate-300">{assetName(id)}</span>
                  <span className="font-mono tnum text-amber-300">{n} unknown</span>
                </div>
                <div className="h-1 overflow-hidden rounded-full bg-white/[0.06]">
                  <span className="block h-full rounded-full bg-amber-400/80" style={{ width: `${(n / (gaps[0]?.[1] || 1)) * 100}%` }} />
                </div>
              </div>
            ))}
            {gaps.length === 0 && <span className="text-[11px] text-slate-500">Every assessed control has evidence.</span>}
          </div>
          <Link to="/assets" className="mt-3 inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
            Collect missing evidence <ArrowRight size={12} aria-hidden="true" />
          </Link>
        </div>
      </div>

      <div className="grid gap-3 lg:grid-cols-[1.25fr_1fr]">
        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">Essential service readiness</h2>
            <span className="ml-auto text-[10px] text-slate-500">procedure · backup · RTO</span>
          </div>
          <div className="tblwrap">
            <table className="tbl min-w-[460px]">
              <thead><tr><th>Service</th><th>RTO</th><th>State</th><th>Failed criteria</th></tr></thead>
              <tbody>
                {services.map((s: any) => (
                  <tr key={s.service_id}>
                    <td className="font-medium text-slate-200">{s.service}</td>
                    <td className="tnum text-slate-400">{s.rto_minutes ? `${s.rto_minutes} min` : '—'}</td>
                    <td>
                      <span className={`inline-flex items-center gap-1 text-[11px] ${s.ready ? 'text-emerald-300' : 'text-amber-300'}`}>
                        {s.ready ? <ShieldCheck size={12} aria-hidden="true" /> : <CircleAlert size={12} aria-hidden="true" />}
                        {s.ready ? 'ready' : 'not ready'}
                      </span>
                    </td>
                    <td className="text-[11px] text-slate-400">{s.failed_criteria?.join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {services.length === 0 && <div className="py-3 text-center text-[12px] text-slate-500">No services recorded.</div>}
          <Link to="/recovery" className="mt-2 inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
            Simulate recovery <ArrowRight size={12} aria-hidden="true" />
          </Link>
          <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
            {readiness?.note ?? 'Readiness requires documented procedures, mapped backup dependencies and a configured RTO.'}
          </p>
        </div>

        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">Latest incidents</h2>
            <span className="ml-auto text-[10px] text-slate-500">{activeIncidents.length} active</span>
          </div>
          <ul className="grid gap-1.5">
            {incidents.slice(-5).reverse().map((i: any) => (
              <li key={i.id} className="flex items-center gap-2 rounded-md border border-line/60 bg-raised/30 px-2 py-1.5">
                <DatabaseZap size={13} className="shrink-0 text-slate-500" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate text-[11.5px] text-slate-200">{i.title}</span>
                <Badge text={String(i.severity ?? 'unknown')} />
                <span className="w-16 shrink-0 text-right text-[10px] uppercase tracking-[0.06em] text-slate-500">{i.status}</span>
              </li>
            ))}
          </ul>
          {incidents.length === 0 && <div className="py-3 text-center text-[12px] text-slate-500">No incidents recorded.</div>}
          <Link to="/incidents" className="mt-2 inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
            Incident queue <ArrowRight size={12} aria-hidden="true" />
          </Link>
        </div>
      </div>

      <div className="grid gap-3 lg:grid-cols-[1.4fr_1fr]">
        <div className="card">
          <div className="mb-1 flex items-baseline gap-2">
            <h2 className="text-[13px]">Top open findings</h2>
            <span className="ml-auto text-[10px] text-slate-500">priority, then risk score</span>
          </div>
          <div className="tblwrap">
            <table className="tbl min-w-[560px]">
              <thead><tr><th>Rule</th><th>Priority</th><th>Asset</th><th>Score</th><th>Detail</th></tr></thead>
              <tbody>
                {top.map((f: any) => (
                  <tr key={f.id}>
                    <td className="whitespace-nowrap font-mono text-[11px] text-slate-200">{f.rule_id}</td>
                    <td><Badge text={String(f.priority ?? f.severity ?? 'unknown')} /></td>
                    <td className="max-w-[10rem] truncate text-slate-400">{assetName(f.asset_id)}</td>
                    <td className="tnum text-slate-300">{f.score ?? '—'}</td>
                    <td className="max-w-[19rem] truncate text-slate-400" title={f.detail}>{f.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {top.length === 0 && <div className="py-3 text-center text-[12px] text-slate-500">No open findings.</div>}
          <Link to="/findings" className="mt-2 inline-flex items-center gap-1 text-[11px] text-accent-soft hover:underline">
            Triage all findings <ArrowRight size={12} aria-hidden="true" />
          </Link>
        </div>

        <div className="card">
          <div className="mb-2 flex items-baseline gap-2">
            <h2 className="text-[13px]">Recent activity</h2>
            <ClipboardCheck size={13} className="ml-auto text-slate-500" aria-hidden="true" />
          </div>
          <ol className="grid gap-1.5">
            {activity.map((a: any) => (
              <li key={a.id} className="grid grid-cols-[auto_1fr] items-start gap-2 text-[11px]">
                <span className="mt-1.5 h-1 w-1 rounded-full bg-slate-600" aria-hidden="true" />
                <span className="min-w-0">
                  <span className="font-mono text-[10px] text-slate-500">{a.actor}</span>{' '}
                  <span className="text-slate-300">{a.action.replace(/_/g, ' ')}</span>
                  <span className="block truncate text-slate-500" title={a.detail}>{a.detail}</span>
                </span>
              </li>
            ))}
          </ol>
          {activity.length === 0 && <div className="py-3 text-center text-[12px] text-slate-500">No activity logged.</div>}
        </div>
      </div>

      <div className="card">
        <div className="mb-2 flex items-baseline gap-2">
          <h2 className="text-[13px]">Open findings by priority</h2>
          <span className="ml-auto font-mono text-[10px] text-slate-500">{open.length} open</span>
        </div>
        <div className="grid gap-2.5">
          {PRIORITY_ORDER.filter((k) => byPriority[k]).map((name) => {
            const value = byPriority[name];
            return (
              <div key={name}>
                <div className="mb-1 flex items-baseline justify-between text-[11px]">
                  <span className="text-slate-300">{name}</span>
                  <span className="font-mono tnum text-slate-400">{value}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                  <div className="h-full rounded-full" style={{
                    width: `${(value / Math.max(1, ...Object.values(byPriority))) * 100}%`,
                    background: name === 'Critical' ? '#EF4444' : name === 'High' ? '#F59E0B' : name === 'Low' ? '#22C55E' : CHART.accent,
                  }} />
                </div>
              </div>
            );
          })}
          {open.length === 0 && <span className="text-[12px] text-slate-500">No open findings.</span>}
        </div>
      </div>
    </Page>
  );
}
