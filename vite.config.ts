import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        // Do not rewrite the path, keep /api prefix so it matches backend and Docker nginx config
        // rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  }
})