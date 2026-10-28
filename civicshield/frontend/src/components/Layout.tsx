import { useState } from 'react';
import { Link, Outlet } from 'react-router-dom';
import { AlertTriangle, Menu, X } from 'lucide-react';
import SiteNav, { BrandMark } from './SiteNav';
import { THEMES, applyTheme, getTheme, type ThemeId } from '../theme';

function aiTone(status: string) {
  if (status === 'online' || status === 'Connected') return 'bg-accent-soft';
  if (status === 'unreachable') return 'bg-red-400';
  return 'bg-amber-400';
}

export default function Layout({ aiStatus }: { aiStatus: string }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [role, setRole] = useState(localStorage.getItem('cs_role') ?? 'admin');
  const [theme, setTheme] = useState<ThemeId>(getTheme());
  const changeRole = (next: string) => {
    setRole(next);
    localStorage.setItem('cs_role', next);
    window.location.reload();
  };
  const changeTheme = (next: ThemeId) => {
    setTheme(next);
    applyTheme(next);
  };
  return (
    <div className="flex min-h-screen bg-ink text-slate-300">
      <a href="#main" className="skip-link">Skip to content</a>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/65 md:hidden" onClick={() => setMobileOpen(false)} aria-hidden="true" />
      )}

      <aside
        className={`${mobileOpen ? 'flex' : 'hidden'} fixed inset-y-0 left-0 z-50 w-[min(248px,86vw)] shrink-0 flex-col border-r border-line bg-rail md:sticky md:top-0 md:flex md:h-screen md:max-h-screen md:w-60`}
        aria-label="Sidebar"
      >
        <div className="flex min-h-[3.5rem] items-center gap-2 border-b border-line px-3 py-2">
          <Link to="/" onClick={() => setMobileOpen(false)} aria-label="CivicShield home" className="min-w-0 rounded-md">
            <BrandMark />
          </Link>
          <button
            className="ml-auto inline-flex h-9 w-9 items-center justify-center rounded-md text-slate-400 hover:bg-white/5 hover:text-white md:hidden"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
          >
            <X size={16} />
          </button>
        </div>

        <SiteNav onNav={() => setMobileOpen(false)} />

        <div className="border-t border-line px-3 py-2.5 text-[10px] text-slate-500">
          <div className="flex items-center gap-2">
            <span className={`h-1.5 w-1.5 rounded-full ${aiTone(aiStatus)}`} aria-hidden="true" />
            <span className="uppercase tracking-[0.1em]">AI</span>
            <span className="font-mono text-slate-400">{aiStatus}</span>
          </div>
          <div className="mt-2 flex items-center gap-1.5">
            <span className="text-[9px] uppercase tracking-[0.08em] text-slate-600">Role</span>
            <select
              value={role}
              onChange={(e) => changeRole(e.target.value)}
              aria-label="Demo account role"
              className="min-w-0 flex-1 rounded border border-line bg-surface px-1.5 py-1 font-mono text-[10px] text-slate-300"
            >
              <option value="admin">admin</option>
              <option value="operator">operator</option>
              <option value="viewer">viewer</option>
            </select>
          </div>
          <div className="mt-2 flex items-center gap-1.5">
            <span className="text-[9px] uppercase tracking-[0.08em] text-slate-600">Theme</span>
            <select
              value={theme}
              onChange={(e) => changeTheme(e.target.value as ThemeId)}
              aria-label="Interface theme"
              className="min-w-0 flex-1 rounded border border-line bg-surface px-1.5 py-1 font-mono text-[10px] text-slate-300"
            >
              {THEMES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </div>
          <div className="mt-1 text-[9.5px] tracking-[0.06em] text-slate-600">
            Demo Owner · {role === 'admin' ? 'full access' : role} · v0.2
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center justify-center gap-1.5 border-b border-amber-500/25 bg-amber-500/[0.07] px-3 py-1 text-[10.5px] tracking-[0.03em] text-amber-300/90">
          <AlertTriangle size={11} aria-hidden="true" className="shrink-0" />
          <span className="truncate">Demo estate — records are stored locally; no production systems are touched</span>
        </div>

        <div className="sticky top-0 z-30 flex min-h-[3.25rem] items-center gap-2 border-b border-line bg-rail/95 px-3 py-1 backdrop-blur md:hidden">
          <button
            className="inline-flex h-10 w-10 items-center justify-center rounded-md text-slate-300 hover:bg-white/5 hover:text-white"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
            aria-expanded={mobileOpen}
          >
            <Menu size={18} />
          </button>
          <BrandMark compact />
          <span className="ml-1 truncate font-display text-[13.5px] font-bold text-white">CivicShield</span>
          <span className="ml-auto flex items-center gap-1.5 text-[10px] text-slate-500">
            <span className={`h-1.5 w-1.5 rounded-full ${aiTone(aiStatus)}`} aria-hidden="true" />
            {aiStatus}
          </span>
        </div>

        <main id="main" tabIndex={-1} className="flex-1 px-3 py-4 pb-10 sm:px-4 md:px-6 md:py-5">
          <div className="app-shell grid content-start gap-4 md:gap-5">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
