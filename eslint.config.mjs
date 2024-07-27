import typescriptEslint from "@typescript-eslint/eslint-plugin";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all
});

export default [
  {
    ignores: [
      "**/logs",
      "**/*.log",
      "**/npm-debug.log*",
      "**/yarn-debug.log*",
      "**/yarn-error.log*",
      "**/lerna-debug.log*",
      "**/.pnpm-debug.log*",
      "**/report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json",
      "**/pids",
      "**/*.pid",
      "**/*.seed",
      "**/*.pid.lock",
      "**/lib-cov",
      "**/coverage",
      "**/*.lcov",
      "**/.nyc_output",
      "**/.grunt",
      "**/bower_components",
      "**/.lock-wscript",
      "build/Release",
      "**/node_modules/",
      "**/jspm_packages/",
      "**/web_modules/",
      "**/*.tsbuildinfo",
      "**/.npm",
      "**/.eslintcache",
      "**/.stylelintcache",
      "**/.rpt2_cache/",
      "**/.rts2_cache_cjs/",
      "**/.rts2_cache_es/",
      "**/.rts2_cache_umd/",
      "**/.node_repl_history",
      "**/*.tgz",
      "**/.yarn-integrity",
      "**/.env",
      "**/.env.development.local",
      "**/.env.test.local",
      "**/.env.production.local",
      "**/.env.local",
      "**/.cache",
      "**/.parcel-cache",
      "**/.next",
      "**/out",
      "**/.nuxt",
      "**/dist",
      "**/.cache/",
      ".vuepress/dist",
      "**/.temp",
      "**/.docusaurus",
      "**/.serverless/",
      "**/.fusebox/",
      "**/.dynamodb/",
      "**/.tern-port",
      "**/.vscode-test",
      ".yarn/cache",
      ".yarn/unplugged",
      ".yarn/build-state.yml",
      ".yarn/install-state.gz",
      "**/.pnp.*",
      "**/.webpack/",
      "**/.svelte-kit",
      "security"
    ]
  },
  ...compat.extends("plugin:@typescript-eslint/eslint-recommended", "plugin:@typescript-eslint/recommended", "prettier"),
  {
    plugins: {
      "@typescript-eslint": typescriptEslint
    },

    languageOptions: {
      globals: {
        ...globals.node
      },

      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module",

      parserOptions: {
        project: ["./tsconfig.json", "./test/tsconfig.json"]
      }
    },

    rules: {
      quotes: ["error", "double"]
    }
  }
];
