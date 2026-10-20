#include <qproto/host.h>
#include <qproto/paths.h>

#include <authum/env.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>

#include <stdio.h>

static authum_bool_t
qproto_try_open(const authum_path_t *dir, const authum_char_t *name, authum_path_t *out_path,
		FILE **out_file)
{
	FILE *f;

	if (authum_null_eq(dir) || authum_path_is_empty(dir))
		return authum_bool_false;
	if (!authum_path_join(out_path, dir, name))
		return authum_bool_false;
	f = fopen(authum_path_as_cstr(out_path), "r");
	if (authum_null_eq(f))
		return authum_bool_false;
	*out_file = f;
	return authum_bool_true;
}

FILE *
qproto_open_data_file(const authum_char_t *name, authum_path_t *out_path)
{
	authum_path_t candidate;
	authum_path_t parent;
	FILE *f;
	const authum_path_t *mod;
	const authum_path_t *game;

	if (authum_null_eq(name) || name[0] == '\0' || authum_null_eq(out_path))
		return authum_null;

	authum_path_clear(out_path);
	f = authum_null;

	mod = authum_host_env_module(&g_qproto_host);
	if (qproto_try_open(mod, name, out_path, &f))
		return f;

	game = authum_host_env_game(&g_qproto_host);
	if (!authum_null_eq(game) && !authum_path_is_empty(game)) {
		if (authum_path_join(&candidate, game, "addons/authum/modules/qproto") &&
		    qproto_try_open(&candidate, name, out_path, &f))
			return f;
		if (authum_path_join(&candidate, game, "addons/qproto") &&
		    qproto_try_open(&candidate, name, out_path, &f))
			return f;
		if (qproto_try_open(game, name, out_path, &f))
			return f;
		if (authum_path_parent(&parent, game) && qproto_try_open(&parent, name, out_path, &f))
			return f;
	}

	/* Default write target when the file is missing. */
	if (!authum_null_eq(mod) && !authum_path_is_empty(mod))
		(void)authum_path_join(out_path, mod, name);
	else if (!authum_null_eq(game) && !authum_path_is_empty(game) &&
		 authum_path_join(&candidate, game, "addons/authum/modules/qproto"))
		(void)authum_path_join(out_path, &candidate, name);

	return authum_null;
}
