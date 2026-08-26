# Examples

| File | What it shows | Command |
|---|---|---|
| [h2c_loopback.mojo](h2c_loopback.mojo) | Cleartext client and server, incremental `feed_input` | `pixi run example-h2c-loopback` |
| [h2_tls_loopback.mojo](h2_tls_loopback.mojo) | One request over TLS with `h2` ALPN | `pixi run example-h2-tls-loopback` |

```sh
python3 tools/fetch_deps.py
pixi run example-h2c-loopback
pixi run example-h2-tls-loopback
```
