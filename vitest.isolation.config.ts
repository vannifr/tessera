import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/isolation/**/*.test.ts'],
    testTimeout: 600000,
    hookTimeout: 600000,
    coverage: { enabled: false },
  },
});
