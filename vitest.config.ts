import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'happy-dom',
    include: ['src/**/*.{test,spec}.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: [
        'src/lib/**',
        'src/stores/**',
        'src/composables/**',
        'src/components/**',
      ],
      exclude: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
    },
  },
})
