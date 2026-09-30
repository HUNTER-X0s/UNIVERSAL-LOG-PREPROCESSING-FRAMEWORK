/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        page: '#F8FAFC',
        surface: {
          DEFAULT: '#FFFFFF',
          alt: '#F1F5F9',
          hover: '#EEF2F7',
        },
        navy: {
          900: '#0F2747',
          800: '#163A63',
          700: '#1E3A5F',
        },
        gov: {
          blue: '#1455A0',
          dark: '#0F4080',
          light: '#EFF6FF',
          border: '#BFDBFE',
          muted: '#DBEAFE',
        },
        border: {
          light: '#E2E8F0',
          medium: '#CBD5E1',
        },
        ok: {
          DEFAULT: '#15803D',
          bg: '#F0FDF4',
          border: '#BBF7D0',
          text: '#14532D',
        },
        warn: {
          DEFAULT: '#B45309',
          bg: '#FFFBEB',
          border: '#FDE68A',
          text: '#92400E',
        },
        danger: {
          DEFAULT: '#B91C1C',
          bg: '#FEF2F2',
          border: '#FECACA',
          text: '#991B1B',
        },
      },
      fontFamily: {
        sans: ['"Noto Sans"', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'Consolas', '"Courier New"', 'monospace'],
      },

      fontSize: {
        // Bumped scale for improved readability across the ULPF platform
        '2xs': ['11px',   { lineHeight: '15px' }],
        xs:    ['13.5px', { lineHeight: '19px' }],
        sm:    ['15px',   { lineHeight: '22px' }],
        base:  ['16.5px', { lineHeight: '25px' }],
        lg:    ['19px',   { lineHeight: '28px' }],
        xl:    ['21px',   { lineHeight: '29px' }],
        '2xl': ['25px',   { lineHeight: '33px' }],
        '3xl': ['31px',   { lineHeight: '39px' }],
        '4xl': ['37px',   { lineHeight: '43px' }],
      },
    },
  },
  plugins: [],
};
