import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Same-origin in dev, so no CORS and the SSE stream behaves like it
      // will in production.
      // Vite's dev proxy streams SSE through unbuffered, so /api/events works
      // as-is. In production the API serves the built SPA itself, so there is
      // no proxy in the path at all. Behind nginx, set proxy_buffering off.
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
})
