#ifndef QPROTO_PATHS_H
#define QPROTO_PATHS_H

#include <authum/char.h>
#include <authum/path.h>

#include <stdio.h>

/*
 * Resolves where to read/write qproto data files (qproto.cfg, qproto_bans.cfg).
 * Search order (first existing wins):
 *   1) <module>/name                 — Authum module dir
 *   2) <game>/addons/authum/modules/qproto/<name>
 *   3) <game>/addons/qproto/<name>
 *   4) <game>/<name>
 *   5) <game>/../<name>
 * If none exist, out_path is set to (1) or (2) so new writes (bans) land with
 * the plugin. Returns an open FILE* for reading, or null if missing.
 */

FILE *qproto_open_data_file(const authum_char_t *name, authum_path_t *out_path);

#endif /* QPROTO_PATHS_H */
