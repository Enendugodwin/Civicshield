const BASE = (import.meta as any).env?.VITE_API_BASE ?? '';
async function req(path: string, init?: RequestInit) {
  const token = localStorage.getItem('cs_token') ?? '';
  const role = localStorage.getItem('cs_role') ?? 'admin';
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Role': role, ...((init?.headers as any) ?? {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${(await res.text()).slice(0, 300)}`);
  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('json')) return res.json();
  return res.text();
}
export const api = {
  get: (p: string) => req(p),
  post: (p: string, body?: unknown) => req(p, { method: 'POST', body: JSON.stringify(body ?? {}) }),
  patch: (p: string, body?: unknown) => req(p, { method: 'PATCH', body: JSON.stringify(body ?? {}) }),
  del: (p: string) => req(p, { method: 'DELETE' }),
  health: () => req('/api/health'),
};
