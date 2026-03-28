import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  build: {
    // Output into the Go embed target so `go build` picks up the compiled assets.
    // Path is relative to the ui/ directory (where vite.config.ts lives).
    outDir: '../registry/handlers/ui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/v2': 'http://localhost:5000',
      '/auth': 'http://localhost:5000',
    },
  },
})
