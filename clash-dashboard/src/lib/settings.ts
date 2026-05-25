export const getApiUrl = () => localStorage.getItem('clash-api-url') || window.location.origin;
export const getSecret = () => {
  const persisted = localStorage.getItem('clash-api-secret');
  if (persisted !== null) {
    return persisted;
  }

  const legacySessionSecret = sessionStorage.getItem('clash-api-secret');
  if (legacySessionSecret !== null) {
    // lgtm[js/clear-text-storage-of-sensitive-data]
    // Intentional: persist LAN dashboard credentials across browser restarts.
    // This secret stays on the current device and should only be used on trusted hosts.
    localStorage.setItem('clash-api-secret', legacySessionSecret);
    return legacySessionSecret;
  }

  return '';
};
export const setApiUrl = (url: string) => localStorage.setItem('clash-api-url', url);
export const setSecret = (s: string) => {
  // lgtm[js/clear-text-storage-of-sensitive-data]
  // Intentional: persist LAN dashboard credentials across browser restarts.
  // This secret stays on the current device and should only be used on trusted hosts.
  localStorage.setItem('clash-api-secret', s);
  sessionStorage.removeItem('clash-api-secret');
};
