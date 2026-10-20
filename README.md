<p align="center">
  <img src="assets/logo.png" alt="qproto" width="280">
</p>

<h1 align="center">qproto</h1>

<p align="center">
  <b>1.0.0</b> — Metamod-P auth plugin for classic HLDS<br>
  dproto-style non-Steam authorization + Vellum ticket protocol
</p>

<p align="center">
  <a href="LICENSE">Apache-2.0</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/darwin128k/raspad-qproto">GitHub</a>
</p>

---

## What it is

Metamod-P plugin for **classic HLDS** (not ReHLDS — use [classic HLDS auth](https://github.com/rehlds/classic HLDS auth) there). Hooks `Steam_NotifyClientConnect`, accepts known emulator tickets, writes AuthID into `client_t::network_userid`.

- RevEmu / RevEmu2013 / SC2009 / OldRevEmu
- sXe Injected (`*HID`)
- **Vellum** (replica ticket protocol; opt-in via `EnableVellum = 1`)
- Setti, NoSteam47/48, SteamPending
- `cid_*` like `dproto.cfg`
- Auto engine layout: classic (~8684) and HLDS **10211**
- Hardware-key bans (`qproto_bans.cfg`)
- C API for other plugins (`include/qproto/qproto_api.h`)

## Install

Ready Linux binary: download `qproto_i386.so` from
[Releases](https://github.com/darwin128k/raspad-qproto/releases) (CI builds it on every `master` push and attaches it to version tags).

1. Put into `cstrike/addons/qproto/`:
   - `qproto_i386.so`
   - `qproto.cfg`
   - `qproto_bans.cfg` (optional)
2. In `addons/metamod/plugins.ini`:

```text
linux addons/qproto/qproto_i386.so
```

3. `meta list` → `qproto` RUN

`qproto.cfg` / `qproto_bans.cfg` search order (first hit wins):

1. `cstrike/addons/qproto/`
2. `cstrike/`
3. HLDS root (next to `hlds_run`)

## Build

```bash
git submodule update --init --recursive
cmake -S . -B build-linux32 -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux32 -j
```

Linux CI (GitHub Actions) builds `qproto_i386.so` on `master` only. Tag `v*` (or run the **Release** workflow with an existing tag) publishes the `.so` as a release asset.

32-bit toolchain required (`-m32`). Output: `qproto_i386.so`.

## Config

See `qproto.cfg` for `Enable*`, `cid_*`, `EngineLayout`, `RejMsg*`, `LoggingMode`.

| `EngineLayout` | Meaning |
| --- | --- |
| `auto` | default — pick classic vs 10211 |
| `classic` / `8684` | older HLDS |
| `10211` | SteamCMD build 10211 |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
