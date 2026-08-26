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
