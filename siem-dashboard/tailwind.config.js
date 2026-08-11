/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{html,ts}'],
  corePlugins: {
    preflight: false, // Prevent resets from clashing with Angular Material
  },
  theme: {
    extend: {
      colors: {
        siem: {
          bg:       '#0d1117',
          surface:  '#161b22',
          raised:   '#1c2128',
          border:   '#30363d',
          primary:  '#e6edf3',
          muted:    '#8b949e',
          faint:    '#6e7681',
          sidebar:  '#0e1419',
        },
        severity: {
          critical: '#da3633',
          high:     '#f85149',
          medium:   '#d29922',
          low:      '#3fb950',
          info:     '#58a6ff',
        },
        brand: {
          orange: '#F46A1F',
          purple: '#7F77DD',
          blue:   '#1f6feb',
          'orange-dim': '#C45114',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Roboto', 'Helvetica Neue', 'sans-serif'],
        mono: ['Consolas', 'JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        card:   '0 1px 3px rgba(0,0,0,.45), 0 1px 0 rgba(255,255,255,.04) inset',
        panel:  '0 4px 20px rgba(0,0,0,.55)',
        modal:  '0 8px 32px rgba(0,0,0,.65)',
        'glow-orange': '0 0 24px rgba(244,106,31,.25)',
        'glow-blue':   '0 0 24px rgba(31,111,235,.25)',
        'glow-purple': '0 0 24px rgba(127,119,221,.25)',
      },
      animation: {
        'fade-in':    'fadeIn .15s ease-out',
        'slide-up':   'slideUp .2s ease-out',
        'pulse-soft': 'pulseSoft 2.5s ease-in-out infinite',
      },
      keyframes: {
        fadeIn:    { from: { opacity: '0' }, to: { opacity: '1' } },
        slideUp:   { from: { transform: 'translateY(6px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        pulseSoft: { '0%,100%': { opacity: '1' }, '50%': { opacity: '.55' } },
      },
    },
  },
  plugins: [],
};
