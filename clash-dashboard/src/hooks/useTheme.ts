import { useState, useEffect } from 'react';

export type Theme = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'clash-rs-theme';

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
    return stored ?? 'system';
  });

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Apply on mount (before first render flicker)
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
    if (stored) applyTheme(stored);
  }, []);

  function setTheme(t: Theme) {
    localStorage.setItem(STORAGE_KEY, t);
    setThemeState(t);
    applyTheme(t);
  }

  return { theme, setTheme };
}
