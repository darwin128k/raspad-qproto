# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Authum client module** (`authum_module_api` / ABI 0.2) → `qproto.so`
- `LoggingMode` bit `rl_host` (4) for authum.log; default remains file-only (2)

### Changed

- Public API renamed to **snake_case** (`qproto_hook_install`, `qproto_log`, …)
- Branch `2.0.0` is Authum-only; Metamod plugin stays on `1.0.0`
- RevEmu Rijndael + SHA-256 via Authum crypto facade (`host->crypto` → lh session API)

### Removed

- Metamod plugin entrypoints (`h_export`, `meta_api`, `dllapi`, …) from this branch
- Vendored `Rijndael` / `sha2` sources (crypto only through Authum/lh)

## [1.0.0] - 2026-10-19

First tagged release of qproto as a Metamod-P plugin for classic HLDS.
See branch `1.0.0` / tag `v1.0.0`.

[Unreleased]: https://github.com/darwin128k/raspad-qproto/compare/v1.0.0...2.0.0
[1.0.0]: https://github.com/darwin128k/raspad-qproto/releases/tag/v1.0.0
