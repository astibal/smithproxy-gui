import {defineConfig} from 'vitest/config';

export default defineConfig({
  base: './',
  build: {
    sourcemap: true,
    target: 'es2022',
  },
  server: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
    },
  },
});
