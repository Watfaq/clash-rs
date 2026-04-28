export const getApiUrl = () => localStorage.getItem('clash-api-url') || window.location.origin;
// Secret is session-scoped (sessionStorage) — not persisted across browser restarts.
export const getSecret = () => sessionStorage.getItem('clash-api-secret') || '';
export const setApiUrl = (url: string) => localStorage.setItem('clash-api-url', url);
export const setSecret = (s: string) => sessionStorage.setItem('clash-api-secret', s);
