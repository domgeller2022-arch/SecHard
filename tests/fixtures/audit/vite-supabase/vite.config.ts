// FIXTURE: minimal Vite config so stack detection has its evidence. No imports: this file is
// typechecked with the test suite and exists only to be seen.
const config = { build: { target: 'es2022' }, plugins: [] };

export = config;
