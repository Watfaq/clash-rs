import { useLayoutEffect, useState } from 'react';

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
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === 'system' || stored === 'light' || stored === 'dark'
      ? stored
      : 'system';
  });

  // useLayoutEffect applies data-theme before paint, preventing flash on load
  useLayoutEffect(() => {
    applyTheme(theme);
  }, [theme]);

  function setTheme(t: Theme) {
    localStorage.setItem(STORAGE_KEY, t);
    setThemeState(t);
  }

  return { theme, setTheme };
}
