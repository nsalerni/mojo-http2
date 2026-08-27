# Contributing to mojo-http2

Thanks for looking at the project. HTTP/2 and HPACK behavior is checked
against h2spec, python-hpack, hyper-h2, and hyperframe.

## Setup

```sh
curl -fsSL https://pixi.sh/install.sh | sh
git clone https://github.com/nsalerni/mojo-http2.git
cd mojo-http2
pixi install
python3 tools/fetch_deps.py
pixi run test
```

## Style

- Public APIs follow the
  [Mojo docstring style](https://github.com/modular/modular/blob/main/mojo/stdlib/docs/docstring-style-guide.md).
- This repo targets Mojo 1.0: `def` only (no `fn`), `comptime` not `alias`,
  `std.`-prefixed imports, and explicit `.copy()` / `^` moves. SNI and
  TLS filesystem paths take `StringSpan` and are copied to `String` at
  the TLS FFI boundary. Tests are plain executables run by
  `tools/run_tests.py` (`mojo test` no longer exists).

## Checks

```sh
pixi run test
pixi run compliance    # if you change protocol behavior
```

HPACK tables are generated from RFC 7541. Do not edit `src/hpack/tables.mojo`
by hand; run `pixi run gen-hpack`.

Fork, branch from `main`, and keep pull requests focused. By contributing,
you agree that your contributions are licensed under
[Apache License 2.0](LICENSE).
