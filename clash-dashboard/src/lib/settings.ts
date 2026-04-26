export const getApiUrl = () => localStorage.getItem('clash-api-url') || window.location.origin;
export const getSecret = () => localStorage.getItem('clash-api-secret') || '';
export const setApiUrl = (url: string) => localStorage.setItem('clash-api-url', url);
export const setSecret = (s: string) => localStorage.setItem('clash-api-secret', s);
