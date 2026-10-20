#ifndef QPROTO_PATHS_H
#define QPROTO_PATHS_H

#include <stdio.h>
#include <stddef.h>

/*
 * Resolves where to read/write qproto data files (qproto.cfg, qproto_bans.cfg).
 * Search order (first existing wins):
 *   1) <gamedir>/addons/qproto/<name>   — drop next to the .so
 *   2) <gamedir>/<name>                 — cstrike/ root
 *   3) <gamedir>/../<name>              — HLDS root (dproto.cfg convention)
 * If none exist, out_path is set to (1) so new writes (bans) land with the plugin.
 * Returns an open FILE* for reading, or NULL if the file is missing.
 */

FILE *qproto_open_data_file(const char *name, char *out_path, size_t out_path_len);

#endif /* QPROTO_PATHS_H */
