// eslint.config.js — V4.1.1 flat config for ESLint v9+
// Uses flat config (eslint.config.js) which is the default in ESLint 9+.
// Older ESLint users can still use this via the FLAT_CONFIG_FILENAME env var.
//
// Run: npx eslint broker/ broker-test/ cli/ sdk/python/secret_broker/
// Zero-deps config (no plugin imports), catches common bugs without opinions.

export default [
  {
    files: ['broker/**/*.js', 'broker-test/**/*.js', 'cli/**/*.js', 'routes/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        // Node.js globals
        process: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        setImmediate: 'readonly',
        global: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        // Node modules
        require: 'readonly',
        module: 'readonly',
        exports: 'writable',
        __dirname: 'readonly',
        __filename: 'readonly',
      },
    },
    rules: {
      // Best practices
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-undef': 'error',
      'no-undef-init': 'error',
      'no-var': 'error',
      'prefer-const': 'warn',
      'no-console': ['warn', { allow: ['warn', 'error'] }], // production: structured log() instead
      'no-debugger': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-with': 'error',
      'no-loop-func': 'warn',
      'no-return-assign': 'warn',
      'no-sequences': 'warn',
      'no-throw-literal': 'error',
      'no-unused-expressions': 'warn',
      'no-useless-call': 'warn',
      'no-useless-concat': 'warn',
      // Style (kept minimal to avoid bike-shedding)
      'no-trailing-spaces': 'warn',
      'no-multiple-empty-lines': ['warn', { max: 2, maxEOF: 1 }],
      eqeqeq: ['error', 'smart'],
      curly: ['error', 'multi-line'],
    },
  },
  // Test files relax some rules
  {
    files: ['broker-test/**/*.js'],
    rules: {
      'no-console': 'off', // tests use console.log/PASS/FAIL
    },
  },
  // Generated/vendor code: ignore
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      'broker/dashboard/**', // generated / hand-written dashboard JS, separate concern
      'broker/experimental/**', // unsupported reference impls
      'sdk/python/**', // Python (different lint tool)
    ],
  },
];
