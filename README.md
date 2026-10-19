<p align="center">
  <img src="assets/logo.png" alt="qproto" width="280">
</p>

<h1 align="center">qproto</h1>

<p align="center">
  <b>1.0.0+</b> — Authum module for classic HLDS<br>
  dproto-style non-Steam authorization + Vellum ticket protocol
</p>

<p align="center">
  <a href="LICENSE">Apache-2.0</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/darwin128k/raspad-qproto">GitHub</a> ·
  <a href="https://github.com/darwin128k/rapad-authum">Authum host</a>
</p>

---

## Where the code lives

**Shipping module:** [rapad-authum](https://github.com/darwin128k/rapad-authum) → `src/modules/qproto/`  
(Authum ABI 0.2 client: `authum_module_api`, host facade, vendored hook/cfg/crypto core).

This repository keeps sample `qproto.cfg`, license/NOTICE, and release history.  
The standalone **Metamod-P** plugin build (`qproto_i386.so` via `plugins.ini`) is **retired**.

## Install (Authum)

1. Build / download `authum_mm.so` and `modules/qproto/qproto.so` from Authum.
2. Drop under `cstrike/addons/authum/` (host) and `addons/authum/modules/qproto/`.
3. List `qproto` in `modules.list`.
4. Put `qproto.cfg` (and optional `qproto_bans.cfg`) next to the module.

Load Authum from Metamod as usual; Authum loads `qproto`.

## Build

```bash
# In the Authum checkout:
git submodule update --init --recursive
# CI / local: clone metamod-p into lib/metamod-p if needed
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAUTHUM_BUILD_QPROTO=ON
cmake --build build --target authum qproto_authum
# → build/modules/qproto/qproto.so
```

## Config

See `qproto.cfg` for `Enable*`, `cid_*`, `EngineLayout`, `RejMsg*`, `LoggingMode`.

| `EngineLayout` | Meaning |
| --- | --- |
| `auto` | default — pick classic vs 10211 |
| `classic` / `8684` | older HLDS |
| `10211` | SteamCMD build 10211 |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
