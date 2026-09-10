export default [
  {
    ignores: [
      '**/node_modules/**',
      '**/coverage/**',
      '**/out/**',
      '**/dist/**',
    ],
  },
  {
    files: ['broker/**/*.js', 'broker-test/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        Buffer: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        clearInterval: 'readonly',
        clearTimeout: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        process: 'readonly',
        setInterval: 'readonly',
        setTimeout: 'readonly',
        structuredClone: 'readonly',
      },
    },
    rules: {
      'no-constant-condition': ['error', { checkLoops: false }],
      'no-control-regex': 'off',
      // The inherited codebase has tracked unused-symbol debt. Keep it visible
      // without blocking unrelated hardening work; new security modules below
      // remain strict.
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      'no-useless-escape': 'off',
    },
  },
  {
    files: [
      'broker/lib/mtls.js',
      'broker/lib/operations-v2.js',
      'broker/lib/outbound-policy.js',
      'broker/routes/v2.js',
      'broker-test/test-mtls.js',
      'broker-test/test-v2-operations.js',
      'broker-test/test-outbound-policy.js',
    ],
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
    },
  },
];
