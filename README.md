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
# Needs Authum headers only (sibling checkout). No HLSDK / metamod-p in this module.
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DAUTHUM_SRC_DIR=../raspad-authum
cmake --build build --target qproto
# → build/modules/qproto/qproto.so
```

32-bit toolchain (`-m32`) required.

## Config

See `qproto.cfg`. `LoggingMode`: `2` = file only, `4` = authum.log only, `6` = both.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
