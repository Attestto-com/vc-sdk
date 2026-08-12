// ESLint 9 flat config.
//
// SOC-60. This repo declared a `lint` script and never installed eslint, so
// the step could neither pass nor fail: CI ran it `continue-on-error: true`,
// which is a step that reports nothing under any outcome. Copied from
// cr-vc-sdk, where the same gap was closed first.
//
// Deliberately narrow. This restores a lint step that runs and can fail; it is
// not the place to introduce a rule set nobody has reviewed, which would either
// bury the build in pre-existing violations or get switched off.
import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**', '*.config.js'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Tests assert on loosely-typed JSON fixtures; `any` there is honest.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
)
