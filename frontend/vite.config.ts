import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The app talks to the API through a relative base URL so the same build works
// behind the nginx proxy (/api) and in the local dev server (proxy below).
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true, // dev preview hosts are dynamic (e.g. *.e2b.app)
    proxy: {
      '/api': {
        target: process.env.CERTMGR_API_URL || 'http://localhost:8000',
        changeOrigin: true,
      },
      '/health': { target: process.env.CERTMGR_API_URL || 'http://localhost:8000', changeOrigin: true },
      '/metrics': { target: process.env.CERTMGR_API_URL || 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
})
