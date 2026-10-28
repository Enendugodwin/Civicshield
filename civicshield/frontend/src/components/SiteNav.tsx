import { NavLink } from 'react-router-dom';
import {
  Activity, FileText, Gauge, LayoutDashboard, Network, Radar, RefreshCw,
  Server, Settings, ShieldAlert, ShieldCheck, Siren, Wrench,
} from 'lucide-react';

type NavItem = { label: string; icon: typeof Gauge; to: string; end?: boolean };

/**
 * Primary navigation mirrors the product brief: the real workflow from
 * infrastructure mapping through assessment, remediation and recovery.
 * The service-health workspace is a secondary demo view of live records.
 */
export const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Overview',
    items: [
      { label: 'Overview', icon: LayoutDashboard, to: '/', end: true },
      { label: 'Service Health', icon: Gauge, to: '/service-health' },
    ],
  },
  {
    label: 'Infrastructure',
    items: [
      { label: 'Infrastructure Map', icon: Network, to: '/map' },
      { label: 'Assets', icon: Server, to: '/assets' },
    ],
  },
  {
    label: 'Security Workflow',
    items: [
      { label: 'Assessments', icon: Activity, to: '/assessments' },
      { label: 'Findings & Risk', icon: ShieldAlert, to: '/findings' },
      { label: 'Remediation', icon: Wrench, to: '/remediation' },
    ],
  },
  {
    label: 'Resilience',
    items: [
      { label: 'RecoveryLab', icon: RefreshCw, to: '/recovery' },
      { label: 'Incidents', icon: Siren, to: '/incidents' },
      { label: 'Threat Intelligence', icon: Radar, to: '/threats' },
    ],
  },
  {
    label: 'Program',
    items: [
      { label: 'Reports', icon: FileText, to: '/reports' },
      { label: 'Settings & Audit', icon: Settings, to: '/settings' },
    ],
  },
];

export default function SiteNav({ onNav }: { onNav?: () => void }) {
  return (
    <nav className="flex-1 overflow-y-auto px-2 pb-3" aria-label="Primary">
      {NAV_GROUPS.map((group, gi) => (
        <div key={group.label} className={gi === 0 ? '' : 'mt-3'}>
          <div className="section-label px-2 pb-1 pt-1">{group.label}</div>
          <ul className="grid gap-0.5">
            {group.items.map((item) => (
              <li key={item.to + item.label}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  onClick={onNav}
                  className={({ isActive }) =>
                    `group flex items-center gap-2.5 rounded-md px-2 py-[7px] text-[12.5px] leading-none border ${
                      isActive
                        ? 'border-accent/30 bg-accent/10 font-semibold text-white'
                        : 'border-transparent text-slate-400 hover:border-line hover:bg-white/[0.035] hover:text-slate-100'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <item.icon
                        size={15}
                        strokeWidth={1.85}
                        aria-hidden="true"
                        className={isActive ? 'shrink-0 text-accent-soft' : 'shrink-0 text-slate-500 group-hover:text-slate-300'}
                      />
                      <span className="truncate">{item.label}</span>
                      {isActive && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-accent-soft" aria-hidden="true" />}
                    </>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="flex min-w-0 items-center gap-2.5">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-accent text-white shadow-panel" aria-hidden="true">
        <ShieldCheck size={17} strokeWidth={2.2} />
      </span>
      {!compact && (
        <span className="min-w-0">
          <span className="block truncate font-display text-[13.5px] font-bold leading-tight text-white">CivicShield</span>
          <span className="block truncate text-[9.5px] uppercase tracking-[0.12em] text-slate-500">Water resilience</span>
        </span>
      )}
    </span>
  );
}
