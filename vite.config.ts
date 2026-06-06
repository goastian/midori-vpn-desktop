import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import pkg from './package.json' with { type: 'json' }

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [vue()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },

  // Tauri: prevent Vite from obscuring Rust errors
  clearScreen: false,
  // Dev server bound to localhost:1420 to match tauri.conf.json
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // File-system polling is only needed on Windows (slow native FS events)
      // and inside Docker bind-mounts. Native events on Linux/macOS are faster.
      usePolling: process.platform === 'win32',
    },
  },

  build: {
    // Split large, rarely-changing third-party code into their own long-cached
    // chunks so the application bundle stays small and route-level lazy loads
    // pay only for their own code. Rolldown (the Vite 8 bundler) requires
    // manualChunks to be a function.
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return
          if (id.includes('@tauri-apps')) return 'tauri'
          if (id.includes('vue-i18n') || id.includes('@intlify')) return 'i18n'
          if (
            id.includes('/vue/') ||
            id.includes('/vue-router/') ||
            id.includes('/pinia/') ||
            id.includes('/@vue/')
          ) {
            return 'vue'
          }
        },
      },
    },
  },
}))
