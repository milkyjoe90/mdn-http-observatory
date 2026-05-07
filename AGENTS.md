# Repository Notes

## Test Environment

This checkout needs `pg_config` on `PATH` so the native `pg-native`/`libpq`
binding can build and load during tests.

```sh
if command -v brew >/dev/null 2>&1 && brew --prefix libpq >/dev/null 2>&1; then
  export PATH="$(brew --prefix libpq)/bin:$PATH"
fi
```

If using NVM, make sure the active Node version also provides npm:

```sh
nvm use 24
```

Verify the environment before running the suite:

```sh
which pg_config
pg_config --version
node --version
npm --version
```

If `require("libpq")` fails because `node_modules/libpq/.../addon.node` is
missing, rebuild the native binding with:

```sh
npm --force rebuild libpq --build-from-source
```

Use the same PATH when running the suite:

```sh
npm --force test
```
