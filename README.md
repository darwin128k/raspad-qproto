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
3. List `qproto` in `addons/authum/modules.list`.
4. Load Authum (ABI 0.3) from Metamod as usual.

Ask it over RCON: `rcon authum qproto info` (all clients) or
`rcon authum qproto info #userid | slot | name` (one client in detail).

qproto only decides *how* a client authenticated and whether that protocol is
allowed. Bans, history and stats are other Authum modules that use qproto's
events — see [docs/events.md](docs/events.md).

## Build

```bash
git submodule update --init --recursive
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
# → build/modules/qproto/qproto.so
ctest --test-dir build
```

Authum comes from `lib/authum` (submodule). CMake pulls in `authum_client` via `add_subdirectory(lib/authum/client)`. No HLSDK / metamod-p in this module. 32-bit toolchain (`-m32`) required.

## Config

Defaults live on `g_qproto_config`; `qproto.cfg` overlays them at start.

- Operator keys / sample file: [`qproto.cfg`](qproto.cfg)
- How load works, custom keys (`engine_layout`, `cid_steam`), extending settings:
  **[docs/config.md](docs/config.md)**
- Authum cfg API (any module): [`lib/authum/docs/cfg.md`](lib/authum/docs/cfg.md)

`logging_mode`: `2` = file only, `4` = authum.log only, `6` = both.

## Docs

| Doc | Topic |
|-----|--------|
| [docs/config.md](docs/config.md) | qproto.cfg load, table vs custom keys |
| [docs/events.md](docs/events.md) | Public contract for other modules: `qproto.client.authorized` / `qproto.client.query`; why no bans |
| [lib/authum/docs/events.md](lib/authum/docs/events.md) | Authum event bus, `authum.client.*` |
| [lib/authum/docs/sandbox.md](lib/authum/docs/sandbox.md) | Module sandbox memory, arrays |
| [lib/authum/docs/commands.md](lib/authum/docs/commands.md) | `authum <module> <cmd>` console / RCON commands |
| [lib/authum/docs/cfg.md](lib/authum/docs/cfg.md) | Authum flat cfg + `authum_client` |
| [lib/authum/docs/path.md](lib/authum/docs/path.md) | `authum_path_t` / host env |
| [lib/authum/docs/writing-a-module.md](lib/authum/docs/writing-a-module.md) | Module ABI / host facade |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
