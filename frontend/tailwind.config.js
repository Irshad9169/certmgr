/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef5fb',
          100: '#d9e8f6',
          500: '#1e3a5f',
          600: '#16293f',
          700: '#0f1a2b',
        },
      },
    },
  },
  plugins: [],
}
