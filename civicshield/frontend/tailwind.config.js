/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // CivicShield design tokens — vault dark blue + secure green
        ink: '#0F172A',
        rail: '#101A2D',
        surface: '#192134',
        raised: '#1F2A41',
        field: '#16243C',
        line: '#26344D',
        primary: '#1E3A5F',
        accent: { DEFAULT: '#059669', soft: '#34D399', dim: '#065F46' },
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
