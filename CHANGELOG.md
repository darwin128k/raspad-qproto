# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-19

First tagged release of qproto as a Metamod-P plugin for classic HLDS.

### Added

- RevEmu-family / sXe / Setti / NoSteam47·48 authorization (dproto-style `cid_*` in `qproto.cfg`)
- Built-in Vellum ticket authorizer (replica protocol); **off by default** — enable with `EnableVellum = 1` in `qproto.cfg` (`cid_Vellum`, `RejMsgVellum`)
- Engine hook via `Steam_NotifyClientConnect` (JMP)
- HLDS layout auto-detect: classic (~8684, `network_userid` @ 0x4a90) and build 10211 (@ 0x6200); `EngineLayout=auto|classic|10211`
- Local `.symtab` symbol resolve when `dlsym` fails (10211)
- Public C API for other plugins (`qproto_api.h`)
- `qproto.cfg` / `qproto_bans.cfg`: search `addons/qproto/` → gamedir → HLDS root (first hit wins)
- Hardware-key bans (`qproto_bans.cfg`)
- Linux CI on `master` (i386 Release) and release workflow that attaches `qproto_i386.so` to tag `v*`
- Ready binary: [Releases](https://github.com/darwin128k/raspad-qproto/releases) (`qproto_i386.so`)

[Unreleased]: https://github.com/darwin128k/raspad-qproto/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/darwin128k/raspad-qproto/releases/tag/v1.0.0
