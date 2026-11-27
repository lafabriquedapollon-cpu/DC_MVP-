import { defineConfig } from 'vitest/config';
export default defineConfig({
  esbuild: { jsx: 'automatic' },
  test: { environment: 'jsdom', include: ['scripts/ci-r02-business.test.tsx'], fileParallelism: false }
});
