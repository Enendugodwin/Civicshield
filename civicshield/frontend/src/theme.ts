/** Theme registry: persisted in localStorage, applied as data-theme on <html>. */
export const THEMES = [
  { id: 'vault', label: 'Vault dark', blurb: 'Default low-light operations theme.' },
  { id: 'light', label: 'Light', blurb: 'Paper surfaces for bright rooms and print-like reading.' },
  { id: 'contrast', label: 'High contrast', blurb: 'Pure-black base with brighter text and stronger borders.' },
] as const;

export type ThemeId = (typeof THEMES)[number]['id'];

const KEY = 'cs_theme';

export function getTheme(): ThemeId {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved && (THEMES as readonly { id: string }[]).some((t) => t.id === saved)) {
      return saved as ThemeId;
    }
  } catch { /* storage unavailable — fall through to default */ }
  return 'vault';
}

export function applyTheme(id: ThemeId): void {
  document.documentElement.dataset.theme = id;
  try {
    localStorage.setItem(KEY, id);
  } catch { /* storage unavailable — theme still applies for this session */ }
}
