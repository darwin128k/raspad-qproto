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
   - (`vellum_keys.txt` is created there by qproto — keep it across updates)
3. List `qproto` in `addons/authum/modules.list`.
4. Load Authum (ABI 0.3) from Metamod as usual.

Ask it over RCON: `rcon authum qproto info` (all clients) or
`rcon authum qproto info #userid | slot | name` (one client in detail).

qproto only decides *how* a client authenticated and whether that protocol is
allowed. Bans, history and stats are other Authum modules that use qproto's
events — see [docs/events.md](docs/events.md).

## Vellum v2 (raspad-revloader clients)

Vellum tickets are **signed** (Ed25519). Each player has a key pair in their
user profile; the SteamID is derived from the public key, and every connect is
signed for this server's address and the player's clock.

- **No SteamID forgery** — without the player's key nobody can produce their
  SteamID; the first key seen for a SteamID is pinned in `vellum_keys.txt`,
  and a different key for that SteamID is refused.
- **No ticket replay** — a ticket collected by one server does not work on
  another (address-bound) or a day later (clock-bound).
- **No machine data** — the player's hostname / disk serial are no longer sent.
- **Old clients refused** — unsigned v1 tickets (raspad-revloader before v2)
  get a logged rejection; players must update the client.

Server setup: on a public server set `vellum_server_ip` in `qproto.cfg` to the
address players connect to (especially behind NAT); otherwise the `ip` cvar is
used, and without it only the port is checked. Rejections are logged with the
reason (`rejected: Vellum ...`). A player who lost their key gets a new
SteamID; to hand them the old one, delete its line from `vellum_keys.txt`.

Ed25519 comes from Authum (`<authum/crypto/ed25519.h>`, built into
`authum_client`) — no newer Authum host is needed on the server.

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

`logging_mode`: `4` = authum.log only (default), `2` = private file, `6` = both.

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
