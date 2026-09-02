import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import pkg from './package.json' with { type: 'json' }

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [vue()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },

  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
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
