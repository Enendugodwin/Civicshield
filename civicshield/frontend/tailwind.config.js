/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // CivicShield design tokens — channel variables so [data-theme]
        // overrides in index.css can re-skin surfaces without touching pages.
        // Opacity modifiers (bg-ink/90, border-line/70) keep working because
        // Tailwind fills <alpha-value> from the channel triplet.
        ink: 'rgb(var(--rgb-bg) / <alpha-value>)',
        rail: 'rgb(var(--rgb-rail) / <alpha-value>)',
        surface: 'rgb(var(--rgb-surface) / <alpha-value>)',
        raised: 'rgb(var(--rgb-raised) / <alpha-value>)',
        field: 'rgb(var(--rgb-field) / <alpha-value>)',
        line: 'rgb(var(--rgb-line) / <alpha-value>)',
        primary: 'rgb(var(--rgb-primary) / <alpha-value>)',
        accent: {
          DEFAULT: '#059669',
          soft: 'rgb(var(--rgb-accent-soft) / <alpha-value>)',
          dim: '#065F46',
        },
      },
      fontFamily: {
        sans: ['"Fira Sans"', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
        display: ['"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      boxShadow: {
        panel: '0 1px 2px rgba(0,0,0,0.28)',
        float: '0 12px 32px rgba(0,0,0,0.42)',
      },
    },
  },
  plugins: [],
};
