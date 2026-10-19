# Changelog

## 1.0.0

First tagged release of qproto as a Metamod-P plugin for classic HLDS.

- RevEmu-family / sXe / Setti / NoSteam47·48 authorization (dproto-style `cid_*` in `qproto.cfg`)
- Built-in Vellum ticket authorizer (replica protocol); **off by default** — enable with `EnableVellum = 1` in `qproto.cfg` (`cid_Vellum`, `RejMsgVellum`)
- Engine hook via `Steam_NotifyClientConnect` (JMP)
- HLDS layout auto-detect: classic (~8684, `network_userid` @ 0x4a90) and build 10211 (@ 0x6200); `EngineLayout=auto|classic|10211`
- Local `.symtab` symbol resolve when `dlsym` fails (10211)
- Public C API for other plugins (`qproto_api.h`)
- `qproto.cfg` / `qproto_bans.cfg`: search `addons/qproto/` → gamedir → HLDS root (first hit wins)
