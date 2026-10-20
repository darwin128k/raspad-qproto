#include <cmath>
#include <extdll.h>
#include <enginecallback.h>

#include "qproto/qproto_data_dir.h"
#include "qproto/qproto_paths.h"

#include <cstdio>
#include <cstring>

FILE *
qproto_open_data_file(const char *name, char *out_path, size_t out_path_len)
{
	if (!name || !out_path || out_path_len == 0)
		return nullptr;

	const char *mod_dir = qproto_get_data_dir();
	if (mod_dir) {
		snprintf(out_path, out_path_len, "%s/%s", mod_dir, name);
		FILE *f = fopen(out_path, "r");
		if (f)
			return f;
	}

	char game_dir[256] = {};
	(*g_engfuncs.pfnGetGameDir)(game_dir);

	const char *patterns[] = {
		"%s/addons/authum/modules/qproto/%s",
		"%s/addons/qproto/%s",
		"%s/%s",
		"%s/../%s",
	};

	for (const char *pattern : patterns) {
		snprintf(out_path, out_path_len, pattern, game_dir, name);
		FILE *f = fopen(out_path, "r");
		if (f)
			return f;
	}

	if (mod_dir)
		snprintf(out_path, out_path_len, "%s/%s", mod_dir, name);
	else
		snprintf(out_path, out_path_len, "%s/addons/authum/modules/qproto/%s", game_dir, name);
	return nullptr;
}
