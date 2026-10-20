#include "qproto/data/dir.h"
#include "qproto/host.h"
#include "qproto/paths.h"

#include <authum/engine.h>
#include <stdio.h>
#include <string.h>

FILE *
qproto_open_data_file(const char *name, char *out_path, size_t out_path_len)
{
	const char *mod_dir;
	char game_dir[256];
	static const char *patterns[] = {
		"%s/addons/authum/modules/qproto/%s",
		"%s/addons/qproto/%s",
		"%s/%s",
		"%s/../%s",
	};
	size_t i;

	if (!name || !out_path || out_path_len == 0)
		return NULL;

	mod_dir = qproto_get_data_dir();
	if (mod_dir) {
		FILE *f;
		snprintf(out_path, out_path_len, "%s/%s", mod_dir, name);
		f = fopen(out_path, "r");
		if (f)
			return f;
	}

	memset(game_dir, 0, sizeof(game_dir));
	authum_engine_get_game_dir(g_qproto_host.engine, game_dir, (authum_usize_t)sizeof game_dir);

	for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
		FILE *f;
		snprintf(out_path, out_path_len, patterns[i], game_dir, name);
		f = fopen(out_path, "r");
		if (f)
			return f;
	}

	if (mod_dir)
		snprintf(out_path, out_path_len, "%s/%s", mod_dir, name);
	else
		snprintf(out_path, out_path_len, "%s/addons/authum/modules/qproto/%s", game_dir, name);
	return NULL;
}
