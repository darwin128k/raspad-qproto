# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-10-21

### Removed

- Dead custom reject strings (`RejMsg*` / `rej_msg_*`): after native Steam auth
  fails, a second `SV_RejectConnection` crashes HLDS, so players only saw the
  engine message. Removed unused cfg keys and helpers.


## [2.0.0] - 2026-10-21

### Added

- **Authum client module** (`authum_module_api` / ABI 0.2) → `qproto.so`
- `lib/authum` git submodule; CMake `add_subdirectory(lib/authum/client)` → link
  `authum_client` (no Authum `.c` compiled into qproto)
- Config via Authum cfg: defaults on `g_qproto_config`, `authum_cfg_apply_items`,
  hand-parsed `EngineLayout` / validated `cid_Steam`
- Paths / logs through `authum_path_t` + `authum_host_env_*` (no ad-hoc `data_dir`)
- `LoggingMode` bit for authum.log (host sink); default remains file-only
- Event contract `<qproto/event.h>`: forward `qproto.client.authorized`
  (`qproto_client_info_t`: protocol, ids, raw key, `long_authid`, connect name
  and time) and query `qproto.client.query` (by index / userid / name)
- Client registry fed by Authum `authum.client.connect` / `disconnect`
  (was never filled on 2.0.0 after the Metamod hooks were dropped); table lives
  in qproto's Authum sandbox
- `authum qproto info [#userid | slot | name]` — console / RCON report of how
  clients authenticated, routed through Authum (no engine command of its own)
- `tests/` (CTest): registry binding / lookup, long authid, `info` command
- Docs: [docs/config.md](docs/config.md), [docs/events.md](docs/events.md)

### Changed

- Module is **pure C11** (`project(qproto C)`); all sources `.c`, strict **snake_case** identifiers
- Public API renamed to **snake_case** (`qproto_hook_install`, `qproto_log`, …)
- Authorizers / config / ticket helpers renamed (`revemu_authorize`, `enable_revemu`, `auth_ticket`, …)
- Branch `2.0.0` is Authum-only; Metamod plugin stays on `1.0.0`
- RevEmu Rijndael + SHA-256 via Authum crypto facade (`authum_host_crypto`)
- Engine calls via Authum host getters (no HLSDK in the module; never `host->field`)

### Removed

- Bans: `qproto_bans.cfg`, `bans.c`, `RejMsgBanned`, ban/unban/kick API — a
  ban module belongs on the event bus, not in the protocol backend
- `qproto/api.h` dlsym API — replaced by events
- `paths.c` fallback search (`addons/qproto`, game root, …) — module dir from
  Authum env only
- `static` functions (module-prefixed bricks instead)

- Metamod plugin entrypoints (`h_export`, `meta_api`, `dllapi`, …) from this branch
- C++ sources / headers (`*.cpp`, `precompiled.h`, unused `qproto_bits.h`)
- Vendored `Rijndael` / `sha2` sources (crypto only through Authum/lh)
- `lib/metamod-p` / HLSDK / `sdk_util` dependency from this branch
- `libstdc++` link / `-fpermissive` (C-only build)

## [1.0.0] - 2026-10-19

First tagged release of qproto as a Metamod-P plugin for classic HLDS.
See branch `1.0.0` / tag `v1.0.0`.

[Unreleased]: https://github.com/darwin128k/raspad-qproto/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/darwin128k/raspad-qproto/releases/tag/v2.0.1
[1.0.0]: https://github.com/darwin128k/raspad-qproto/releases/tag/v1.0.0
