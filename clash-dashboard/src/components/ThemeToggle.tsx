import { Monitor, Sun, Moon } from 'lucide-react';
import { useTheme, type Theme } from '../hooks/useTheme';

const OPTIONS: { value: Theme; icon: React.ReactNode; label: string }[] = [
  { value: 'system', icon: <Monitor size={13} />, label: 'System' },
  { value: 'light',  icon: <Sun size={13} />,     label: 'Light'  },
  { value: 'dark',   icon: <Moon size={13} />,    label: 'Dark'   },
];

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div
      role="group"
      aria-label="Theme"
      className="flex items-center rounded-full p-0.5 flex-shrink-0"
      style={{ background: 'var(--color-fill-medium)' }}
      title="Toggle theme"
    >
      {OPTIONS.map(({ value, icon, label }) => {
        const active = theme === value;
        return (
          <button
            key={value}
            onClick={() => setTheme(value)}
            title={label}
            aria-label={label}
            aria-pressed={active}
            className="w-7 h-6 rounded-full flex items-center justify-center transition-all"
            style={{
              background: active ? 'var(--color-input-focus-bg)' : 'transparent',
              color: active ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
              boxShadow: active ? '0 1px 3px rgba(0,0,0,0.12)' : 'none',
            }}
          >
            {icon}
          </button>
        );
      })}
    </div>
  );
}
