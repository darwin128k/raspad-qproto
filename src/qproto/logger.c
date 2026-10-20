#include <qproto/logger.h>

#include <authum/env.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>

authum_logger_t g_qproto_logger;

void
qproto_logger_start(const authum_host_t *host, authum_logger_sink_t sinks)
{
	authum_path_t path;
	const authum_path_t *mod;
	const authum_path_t *game;

	authum_logger_close(&g_qproto_logger);
	authum_logger_init(&g_qproto_logger, host, sinks, "qproto");

	if ((sinks & authum_logger_sink_file) == 0u)
		return;

	authum_path_clear(&path);
	mod = authum_host_env_module(host);
	if (!authum_null_eq(mod) && !authum_path_is_empty(mod)) {
		if (!authum_path_join(&path, mod, "qproto.log")) {
			authum_logger_error(&g_qproto_logger, "qproto.log path too long");
			return;
		}
	} else {
		authum_path_t base;

		game = authum_host_env_game(host);
		if (authum_null_eq(game) || authum_path_is_empty(game) ||
		    !authum_path_join(&base, game, "addons/authum/modules/qproto") ||
		    !authum_path_join(&path, &base, "qproto.log")) {
			authum_logger_error(&g_qproto_logger,
					    "qproto.log open FAILED: no module/game dir in host env");
			return;
		}
	}

	if (authum_logger_open_file(&g_qproto_logger, authum_path_as_cstr(&path)))
		authum_logger_info(&g_qproto_logger, "qproto.log opened: %s",
				   authum_path_as_cstr(&path));
	else
		authum_logger_error(&g_qproto_logger, "qproto.log open FAILED: %s",
				    authum_path_as_cstr(&path));
}

void
qproto_logger_stop(void)
{
	authum_logger_close(&g_qproto_logger);
}
