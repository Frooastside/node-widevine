import globals from 'globals'
import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import prettier from 'eslint-config-prettier'

export default [
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    { files: ['src/**/*.{js,mjs,cjs,ts}'] },
    {
        rules: {
            'no-console': 2,
            'react/prop-types': 0,
            'react-hooks/exhaustive-deps': 0,
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-unsafe-declaration-merging': 'warn',
            '@typescript-eslint/no-unused-vars': 'warn',
            '@typescript-eslint/no-unused-expressions': 'warn',
            indent: ['error', 4],
            'linebreak-style': ['warn', 'windows'],
            quotes: ['error', 'single', { avoidEscape: true }]
        },
        languageOptions: { globals: globals.browser }
    },
    prettier
]
