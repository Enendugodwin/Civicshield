import { api } from '../api';

export type AssetStatus = 'Down' | 'Degraded' | 'At Risk' | 'Recovering' | 'Operational';
export interface Asset {
  id: string; name: string; kind: string; region: string; owner: string;
  status: AssetStatus; severity: 'Critical' | 'High' | 'Medium' | 'Low';
  service: string; incidentId: string; lat: number; lon: number;
  criticality: string; findings: number; backupReady: boolean;
}
export interface ServiceHealth { id: string; name: string; status: AssetStatus; availability: number; slo: number; dependsOn: string[]; beneficiaries: number; }
export interface Finding { id: number; rule_id: string; asset_id: string; severity: string; status: string; detail: string; score: number; priority: string; }
export interface Incident { id: number; title: string; status: string; }
export interface Dataset {
  assets: Asset[]; services: ServiceHealth[]; findings: Finding[];
  incidents: Incident[]; source: 'Connected' | 'Demo' | 'Offline';
  aiMode: string; generatedAt: string;
}

// Deterministic synthetic geo (illustrative only — not real infrastructure).
const GEO: Record<string, [number, number, string]> = {
  '1': [7.55, 4.55, 'osun-east'], '2': [7.48, 4.42, 'south-west'],
  '3': [7.52, 4.60, 'central'], '4': [7.50, 4.50, 'central'],
  '5': [7.53, 4.58, 'central'], '6': [7.56, 4.48, 'osun-east'],
  '7': [7.46, 4.40, 'south-west'], '8': [7.49, 4.44, 'plant'],
  '9': [7.51, 4.61, 'osun-east'], '10': [7.54, 4.52, 'central'],
};
const SEED_ASSETS = [
  ['1', 'admin-ws-01', 'workstation', 'ops-team', 'Safe Water Delivery'],
  ['2', 'ops-ws-01', 'workstation', 'ops-team', 'Plant Monitoring'],
  ['3', 'idp-01', 'directory', 'it-team', 'Safe Water Delivery'],
  ['4', 'app-01', 'server', 'it-team', 'Billing Service'],
  ['5', 'db-01', 'database', 'it-team', 'Billing Service'],
  ['6', 'gw-01', 'firewall', 'net-team', 'Safe Water Delivery'],
  ['7', 'bkp-01', 'backup', 'it-team', 'Safe Water Delivery'],
  ['8', 'wmon-01', 'workstation', 'ops-team', 'Plant Monitoring'],
  ['9', 'log-01', 'monitoring', 'it-team', 'Plant Monitoring'],
  ['10', 'billing-saas', 'external', 'finance', 'Billing Service'],
];

function deriveStatus(raw: string, crit: number, sev: string): AssetStatus {
  if (raw === 'degraded') return 'Degraded';
  if (crit >= 65) return 'Down';
  if (sev === 'critical') return 'Degraded';
  if (crit >= 40) return 'At Risk';
  if (raw === 'recovering') return 'Recovering';
  return 'Operational';
}

export async function loadDataset(): Promise<Dataset> {
  try {
    const [assets, services, findings, incidents, health] = await Promise.all([
      api.get('/api/assets'), api.get('/api/services'), api.get('/api/findings'),
      api.get('/api/incidents'), api.health().catch(() => ({})),
    ]);
    const byAsset = new Map<string, Finding[]>();
    for (const f of findings as Finding[]) {
      const k = String(f.asset_id);
      if (!byAsset.has(k)) byAsset.set(k, []);
      byAsset.get(k)!.push(f);
    }
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1 } as Record<string, number>;
    const list: Asset[] = (assets as any[]).map((a: any, i: number) => {
      const k = String(a.id);
      const fl = byAsset.get(k) ?? [];
      const top = fl.sort((x, y) => (sevRank[String(y.severity).toLowerCase()] ?? 0) - (sevRank[String(x.severity).toLowerCase()] ?? 0))[0];
      const score = Math.max(0, ...fl.map((f) => f.score ?? 0));
      const sev = top ? cap(String(top.severity)) : 'Low';
      const [lat, lon, region] = GEO[k] ?? [7.5 + i * 0.01, 4.5 + i * 0.01, a.zone ?? 'central'];
      return {
        id: k, name: a.hostname || a.name, kind: a.kind, region,
        owner: mockOwner(k), status: deriveStatus(a.status, score, String(top?.severity ?? '')),
        severity: sev as Asset['severity'], service: mockService(k),
        incidentId: fl.length ? `INC-${1000 + Number(k)}` : '',
        lat, lon, criticality: cap(a.criticality ?? 'low'),
        findings: fl.length, backupReady: k === '7',
      };
    });
    const svc: ServiceHealth[] = (services as any[]).slice(0, 3).map((s: any, i: number) => {
      const deps = list.filter((a) => a.service === s.name);
      const down = deps.filter((a) => a.status === 'Down' || a.status === 'Degraded').length;
      return {
        id: String(s.id), name: s.name,
        status: down > 0 ? 'Degraded' : 'Operational',
        availability: down > 0 ? 98.2 - down : 99.98, slo: 99.5,
        dependsOn: deps.map((a) => a.name),
        beneficiaries: [52000, 88000, 31000][i] ?? 10000,
      };
    });
    return {
      assets: list, services: svc, findings: findings as Finding[],
      incidents: incidents as Incident[], source: 'Connected',
      aiMode: (health as any)?.ai?.available ? 'Muse Spark live' : 'Deterministic fallback (AI unavailable)',
      generatedAt: new Date().toISOString(),
    };
  } catch {
    return mockDataset('Offline');
  }
}

function cap(s: string) { return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase(); }
function mockOwner(k: string) {
  return { '1': 'ops-team', '2': 'ops-team', '3': 'it-team', '4': 'it-team', '5': 'it-team', '6': 'net-team', '7': 'it-team', '8': 'ops-team', '9': 'it-team', '10': 'finance' }[k] ?? 'unassigned';
}
function mockService(k: string) {
  return { '1': 'Safe Water Delivery', '2': 'Plant Monitoring', '3': 'Safe Water Delivery', '4': 'Billing Service', '5': 'Billing Service', '6': 'Safe Water Delivery', '7': 'Safe Water Delivery', '8': 'Plant Monitoring', '9': 'Plant Monitoring', '10': 'Billing Service' }[k] ?? 'Safe Water Delivery';
}

export function mockDataset(source: 'Demo' | 'Offline'): Dataset {
  const spec: [AssetStatus, Asset['severity'], number][] = [
    ['Degraded', 'High', 2], ['Recovering', 'Critical', 3], ['Degraded', 'Medium', 1],
    ['Down', 'Critical', 4], ['At Risk', 'High', 2], ['Operational', 'Low', 0],
    ['At Risk', 'High', 1], ['Operational', 'Low', 0], ['Degraded', 'Medium', 2], ['Operational', 'Low', 0],
  ];
  const assets: Asset[] = SEED_ASSETS.map(([id, name, kind, owner, service], i) => {
    const [lat, lon, region] = GEO[id]!;
    return {
      id, name, kind, region, owner, status: spec[i][0], severity: spec[i][1],
      service, incidentId: spec[i][2] ? `INC-${1000 + Number(id)}` : '',
      lat, lon, criticality: i < 3 ? 'Critical' : 'High',
      findings: spec[i][2], backupReady: id === '7',
    };
  });
  return {
    assets, source, aiMode: 'Deterministic fallback (AI unavailable)',
    generatedAt: new Date().toISOString(),
    services: [
      { id: '1', name: 'Safe Water Delivery', status: 'Degraded', availability: 97.4, slo: 99.5, dependsOn: ['app-01', 'db-01', 'gw-01'], beneficiaries: 88000 },
      { id: '2', name: 'Billing Service', status: 'Degraded', availability: 98.9, slo: 99.5, dependsOn: ['app-01', 'db-01'], beneficiaries: 88000 },
      { id: '3', name: 'Plant Monitoring', status: 'Operational', availability: 99.98, slo: 99.9, dependsOn: ['wmon-01', 'log-01'], beneficiaries: 12000 },
    ],
    findings: [], incidents: [],
  };
}

function csvCell(v: string): string {
  return /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
}

export function toCsv(rows: Asset[]): string {
  const head = 'asset,region,status,severity,service,incident\n';
  return head + rows.map((a) => [a.name, a.region, a.status, a.severity, a.service, a.incidentId].map(csvCell).join(',')).join('\n');
}
