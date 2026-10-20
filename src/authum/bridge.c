#include "bridge.h"
#include "host_crypto.h"
#include "host_engine.h"

#include "qproto/qproto_bans.h"
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_data_dir.h"
#include "qproto/qproto_hook.h"
#include "qproto/qproto_logger.h"

authum_bool_t
qproto_authum_start(authum_host_t *host)
{
	if (authum_null_eq(host))
		return authum_bool_false;

	qproto_host_crypto_bind(host);
	qproto_host_engine_bind(host);

	/* Host sink only until cfg loads LoggingMode. */
	authum_logger_init(&g_qproto_logger, host, authum_logger_sink_host, "qproto");

	if (!qproto_host_crypto_ready()) {
		authum_logger_error(&g_qproto_logger, "host crypto missing (authum_host_t.crypto)");
		return authum_bool_false;
	}
	if (!qproto_host_engine_ready()) {
		authum_logger_error(&g_qproto_logger, "host engine missing (authum_host_t.engine)");
		return authum_bool_false;
	}

	if (!authum_null_eq(host->module_dir) && host->module_dir[0])
		qproto_set_data_dir(host->module_dir);

	qproto_cfg_init();
	qproto_logger_start(host, (authum_logger_sink_t)g_qproto_config.logging_mode);
	qproto_cfg_load();
	qproto_logger_start(host, (authum_logger_sink_t)g_qproto_config.logging_mode);

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
	qproto_host_engine_bind(authum_null);
	qproto_host_crypto_bind(authum_null);
}
