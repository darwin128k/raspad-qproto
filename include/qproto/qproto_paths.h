#pragma once

#include <cstdio>
#include <cstddef>

// Resolves where to read/write qproto data files (qproto.cfg, qproto_bans.cfg).
// Search order (first existing wins):
//   1) <gamedir>/addons/qproto/<name>   — drop next to the .so
//   2) <gamedir>/<name>                 — cstrike/ root
//   3) <gamedir>/../<name>              — HLDS root (dproto.cfg convention)
// If none exist, outPath is set to (1) so new writes (bans) land with the plugin.
// Returns an open FILE* for reading, or nullptr if the file is missing.

FILE* Qproto_OpenDataFile(const char* name, char* outPath, size_t outPathLen);
