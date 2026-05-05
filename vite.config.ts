import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [vue()],

  // Tauri: prevent Vite from obscuring Rust errors
  clearScreen: false,
  // Dev server bound to localhost:1420 to match tauri.conf.json
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // On Windows tell watchers to use polling
      usePolling: true,
    },
  },
}))
