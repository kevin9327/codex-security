# Python frontend patch

The patch is based on `py-ast@1.16.0`, upstream commit `fe6c62c1ff23ed9bb933a9daa67115e494e4ca9c`. Its tagged TypeScript sources match the published source map byte for byte.

Apply `py-ast.source.patch` to that upstream checkout, then run `npm install --ignore-scripts` and `npm run build` using the existing registry configuration. The existing build compiles the typed CJS data loader before Rollup emits both public entrypoints and declarations. The generated patch is maintained with ordinary `pnpm patch py-ast@1.16.0` and `pnpm patch-commit`; no source extraction runs during installation or plugin builds.

Copy `dist/index.esm.js`, `dist/index.cjs`, `dist/index.d.ts`, `dist/unicode-data.cjs`, into the editable package and copy the added license files into its `dist` directory. Source-map links are omitted because the distributed maps describe the original source. Keep `packageExtensions` pinned to `@unicode/unicode-15.0.0@2.0.2`.

The Jamo name components are generated from Unicode 15.0 `DerivedName.txt` (SHA-256 `f76288153e20de185a40f7ee6e0e365f3c6c80e9e3019b5aa0afc8ac2c1b15f2`) and verified against all 11,172 Hangul names. Name tables load only when a named escape is parsed.

Tests exercise the installed package through its public API. Select the Python 3.12 baseline with `feature_version: 12`; this currently gates the measured newer syntax rather than claiming complete emulation of every older Python release. Preview selection and byte budgeting remain outside this dependency.
