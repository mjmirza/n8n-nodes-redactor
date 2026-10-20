import { configWithoutCloudSupport } from '@n8n/node-cli/eslint';

// Self-hosted profile until the vault moves off the filesystem in 2.0.0.
export default [
  ...configWithoutCloudSupport,
  {
    // Test fixtures cast freely and probe internals; production code stays strict.
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
];
