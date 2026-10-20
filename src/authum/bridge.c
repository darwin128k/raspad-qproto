#include "bridge.h"

#include "qproto/bans.h"
#include "qproto/cfg.h"
#include "qproto/data/dir.h"
#include "qproto/hook.h"
#include "qproto/host.h"
#include "qproto/logger.h"

authum_host_t g_qproto_host;

authum_bool_t
qproto_authum_start(authum_host_t *host)
{
	if (authum_null_eq(host))
		return authum_bool_false;

	g_qproto_host = *host;

	/* Host sink only until cfg loads LoggingMode. */
	authum_logger_init(&g_qproto_logger, &g_qproto_host, authum_logger_sink_host, "qproto");

	if (authum_null_eq(g_qproto_host.crypto)) {
		authum_logger_error(&g_qproto_logger, "host crypto missing (authum_host_t.crypto)");
		return authum_bool_false;
	}
	if (authum_null_eq(g_qproto_host.engine)) {
		authum_logger_error(&g_qproto_logger, "host engine missing (authum_host_t.engine)");
		return authum_bool_false;
	}

	if (!authum_null_eq(g_qproto_host.module_dir) && g_qproto_host.module_dir[0])
		qproto_set_data_dir(g_qproto_host.module_dir);

	qproto_cfg_init();
	qproto_logger_start(&g_qproto_host, g_qproto_config.logging_sinks);
	qproto_cfg_load();
	qproto_logger_start(&g_qproto_host, g_qproto_config.logging_sinks);

	authum_logger_info(&g_qproto_logger, "Authum module start — data dir: %s",
			   qproto_get_data_dir() ? qproto_get_data_dir() : "(unset)");
	authum_logger_info(&g_qproto_logger,
			   "qproto 2.0.0 under Authum ABI 0.2 — installing Steam_NotifyClientConnect hook");

	qproto_bans_load();

	if (!qproto_hook_install()) {
		authum_logger_error(&g_qproto_logger, "qproto_hook_install FAILED");
		qproto_logger_stop();
		return authum_bool_false;
	}
	authum_logger_info(&g_qproto_logger, "hook installed OK");
	return authum_bool_true;
}

void
qproto_authum_stop(void)
{
	qproto_hook_remove();
	authum_logger_info(&g_qproto_logger, "Authum module stop — hook removed");
	qproto_logger_stop();
	g_qproto_host.log = 0;
	g_qproto_host.engine_funcs = 0;
	g_qproto_host.globals = 0;
	g_qproto_host.module_dir = authum_null;
	g_qproto_host.crypto = authum_null;
	g_qproto_host.engine = authum_null;
}
