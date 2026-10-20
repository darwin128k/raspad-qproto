#include "qproto/qproto_logger.h"
#include "qproto/qproto_data_dir.h"

#include <authum/engine.h>
#include <stdio.h>
#include <string.h>

authum_logger_t g_qproto_logger;

void
qproto_logger_start(const authum_host_t *host, authum_logger_sink_t sinks)
{
	authum_char_t path[512];
	const authum_char_t *mod_dir;

	authum_logger_close(&g_qproto_logger);
	authum_logger_init(&g_qproto_logger, host, sinks, "qproto");

	if ((sinks & authum_logger_sink_file) == 0u)
		return;

	mod_dir = qproto_get_data_dir();
	if (!authum_null_eq(mod_dir) && mod_dir[0] != '\0') {
		snprintf(path, sizeof path, "%s/qproto.log", mod_dir);
	} else if (!authum_null_eq(host) && !authum_null_eq(host->engine)) {
		authum_char_t game_dir[256];
		memset(game_dir, 0, sizeof game_dir);
		authum_engine_get_game_dir(host->engine, game_dir, (authum_usize_t)sizeof game_dir);
		snprintf(path, sizeof path, "%s/addons/authum/modules/qproto/qproto.log", game_dir);
	} else {
		authum_logger_error(&g_qproto_logger, "qproto.log open FAILED: no module/game dir");
		return;
	}

	if (authum_logger_open_file(&g_qproto_logger, path))
		authum_logger_info(&g_qproto_logger, "qproto.log opened: %s", path);
	else
		authum_logger_error(&g_qproto_logger, "qproto.log open FAILED: %s", path);
}

void
qproto_logger_stop(void)
{
	authum_logger_close(&g_qproto_logger);
}
