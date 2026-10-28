// Auth token helpers (used by api.ts).
export const TOKEN_KEY = 'cs_token';
export const getToken = () => localStorage.getItem(TOKEN_KEY) ?? '';
export const setToken = (t: string) => localStorage.setItem(TOKEN_KEY, t);
