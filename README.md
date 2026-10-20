<p align="center">
  <img src="assets/logo.png" alt="qproto" width="280">
</p>

<h1 align="center">qproto</h1>

<p align="center">
  <b>2.0.0</b> — Authum module for classic HLDS (pure C11)<br>
  dproto-style non-Steam authorization + Vellum ticket protocol
</p>

<p align="center">
  <a href="LICENSE">Apache-2.0</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/darwin128k/raspad-qproto">GitHub</a> ·
  <a href="https://github.com/darwin128k/raspad-authum">Authum host</a>
</p>

---

## Branches

| Branch | Product |
|--------|---------|
| `1.0.0` / `master` | Metamod-P plugin `qproto_i386.so` |
| `2.0.0` | Authum client module `qproto.so` (pure C11, this line) |

## Install (Authum)

1. Build `qproto.so` (below) or take a CI artifact.
2. Put under `cstrike/addons/authum/modules/qproto/`:
   - `qproto.so`
   - `qproto.cfg`
   - `qproto_bans.cfg` (optional)
3. List `qproto` in `addons/authum/modules.list`.
4. Load Authum from Metamod as usual.

## Build

```bash
git submodule update --init --recursive
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target qproto
# → build/modules/qproto/qproto.so
```

Authum comes from `lib/authum` (submodule). CMake pulls in `authum_client` via `add_subdirectory(lib/authum/client)`. No HLSDK / metamod-p in this module. 32-bit toolchain (`-m32`) required.

## Config

Defaults live on `g_qproto_config`; `qproto.cfg` overlays them at start.

- Operator keys / sample file: [`qproto.cfg`](qproto.cfg)
- How load works, custom keys (`EngineLayout`, `cid_Steam`), extending settings:
  **[docs/config.md](docs/config.md)**
- Authum cfg API (any module): [`lib/authum/docs/cfg.md`](lib/authum/docs/cfg.md)

`LoggingMode`: `2` = file only, `4` = authum.log only, `6` = both.

## Docs

| Doc | Topic |
|-----|--------|
| [docs/config.md](docs/config.md) | qproto.cfg load, table vs custom keys |
| [lib/authum/docs/cfg.md](lib/authum/docs/cfg.md) | Authum flat cfg + `authum_client` |
| [lib/authum/docs/path.md](lib/authum/docs/path.md) | `authum_path_t` / host env |
| [lib/authum/docs/writing-a-module.md](lib/authum/docs/writing-a-module.md) | Module ABI / host facade |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
