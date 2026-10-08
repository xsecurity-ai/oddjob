// ESLint flat config for the Oddjob UI.
//
// ── Do not add typescript-eslint ────────────────────────────────────────
// It cannot load here. This project compiles with TypeScript 7, the native
// (Go) port, which no longer exports the old JavaScript compiler API that
// typescript-eslint is built on. npm refuses the pair outright (its peer
// range is `typescript@>=4.8.4 <6.1.0`), and forced past that the parser
// reads `ts.versionMajorMinor`, sees 7, and throws before it parses a
// single file. There is a documented workaround — install a second,
// side-by-side TypeScript 6 for the linter to read the API out of — and it
// was deliberately not taken: it buys one extra finding on this codebase
// in exchange for two TypeScripts in the tree and an editor that loses its
// workspace tsserver.
// https://github.com/typescript-eslint/typescript-eslint/issues/10940
//
// So the TypeScript here is parsed by Babel, which reads the syntax
// without needing the compiler, and the rules that matter are the React
// hooks ones. Everything typescript-eslint would have added about *types*
// is already enforced, and enforced better, by `tsc` itself: tsconfig.json
// sets strict, noUnusedLocals, noUnusedParameters and
// noFallthroughCasesInSwitch, and `npm run typecheck` is a separate gate.
//
// When typescript-eslint supports TS >= 7.1 (the issue above), revisiting
// this is worthwhile — type-aware rules are the part that would actually
// earn its keep, and they are the part that is missing today.
//
// ── Why there is no eslint-plugin-react-refresh ─────────────────────────
// It was tried. Its one rule, only-export-components, fires fifteen times
// here and every hit is the same two deliberate shapes: a context hook
// sitting beside the provider it belongs to (useAuth, useAppearance,
// useHostModal) and a domain helper sitting beside the dialog that is its
// only caller, each with a long comment explaining the pairing. The only
// consequence of any of them is that Vite does a full reload instead of a
// hot swap, in dev. Splitting eleven modules up to avoid that would make
// the code harder to read to make the dev server marginally nicer, so the
// rule would have been switched off — and a plugin whose only rule is off
// is a dependency that does nothing. It is not installed.

import js from '@eslint/js'
import babelParser from '@babel/eslint-parser'
import reactHooks from 'eslint-plugin-react-hooks'

export default [
  {
    // dist/ is build output and public/ is copied verbatim. Linting
    // either one reports on code nobody here wrote.
    ignores: ['dist/**', 'public/**', 'node_modules/**'],
  },

  {
    // An eslint-disable that suppresses nothing is how this repository's
    // one pre-existing suppression came to be inert for its whole life:
    // it was written on the line *below* the useMemo it was meant to
    // cover, so it silenced the blank line after it. ESLint reports that
    // by default but only as a warning, which exits 0 and so would never
    // have failed a build. An error, so the next one is caught.
    linterOptions: { reportUnusedDisableDirectives: 'error' },
  },

  js.configs.recommended,

  // Babel reads the TypeScript syntax and hands ESLint the JavaScript
  // underneath — no compiler, no program, no type information.
  //
  // The syntax is turned on through `parserOpts.plugins` rather than by
  // listing @babel/preset-typescript. Under Babel 8 the preset route does
  // not reach the parser from @babel/eslint-parser at all: every .ts file
  // still comes back "Missing initializer in const declaration" at the
  // first type annotation. Naming the parser plugins works, and it drops
  // a dependency rather than adding one.
  //
  // `requireConfigFile: false` because this project has no babel.config.js
  // and should not grow one: Vite builds through esbuild/rolldown, so
  // Babel is here for the linter and nothing else.
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: { babelrc: false, configFile: false,
                        parserOpts: { plugins: ['typescript'] } },
      },
    },
  },
  {
    // `jsx` only for .tsx. In a .ts file it would make `<T>expr`, the
    // legacy type assertion, parse as an element instead.
    files: ['**/*.tsx'],
    languageOptions: {
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: { babelrc: false, configFile: false,
                        parserOpts: { plugins: ['typescript', 'jsx'] } },
      },
    },
  },

  // The hooks rules are the reason this linter exists. A hook called
  // after an early return is a hard React error that renders as a blank
  // page, and it has happened here before — test/hooks.check.mjs is the
  // hand-rolled check written after that outage. `rules-of-hooks` is the
  // real tool for it and catches the conditional and in-callback cases
  // that a brace counter cannot see.
  reactHooks.configs.flat['recommended-latest'],

  {
    files: ['**/*.{ts,tsx}'],
    rules: {
      // A missing dependency is a stale closure, which here means a grid
      // that silently stops refreshing. Promoted from the plugin's
      // default `warn` so it fails the build like the hooks-order check
      // next to it does.
      'react-hooks/exhaustive-deps': 'error',

      // OFF: this is a React Compiler performance rule, not a correctness
      // one, and every one of the nine places it fires here is the same
      // deliberate, commented pattern — seeding an editable form from a
      // query once the server answers, or clearing it when the engagement
      // changes. Satisfying it means restructuring six forms around `key`
      // remounts to save one render, in a tool whose config forms edit
      // live engagement data. Worth revisiting on its own; not worth
      // doing as a side effect of adding a linter.
      'react-hooks/set-state-in-effect': 'off',

      // OFF for TypeScript: `tsc` resolves these, and it is the only one
      // of the two that can. To ESLint, reading this file through Babel
      // with the types stripped, every DOM global and every name used
      // only in a type position is undeclared.
      'no-undef': 'off',

      // OFF for TypeScript, and `tsc` keeps it: tsconfig.json already
      // sets noUnusedLocals and noUnusedParameters, which catch the same
      // thing, exempt `_`-prefixed names the way the code here expects
      // (`const { targets: _planned, ...flags }`), and — the part that
      // decides it — understand JSX. ESLint's own rule does not: reading
      // a Babel AST with no JSX-awareness it counts every component
      // imported for use in markup as unused, which was 820 findings
      // across this codebase and not one of them real.
      'no-unused-vars': 'off',
    },
  },

  {
    // Node, not the browser. Only the .mjs harness needs this: no-undef
    // is off for TypeScript above, so the .ts files here and
    // vite.config.ts are already covered. Without it, no-undef reports
    // the `console` and `process` that test/hooks.check.mjs is entitled
    // to.
    files: ['test/**/*.mjs'],
    languageOptions: {
      globals: { process: 'readonly', console: 'readonly' },
    },
  },
]
