#include <bridge.h>

#include <qproto/bans.h>
#include <qproto/config.h>
#include <qproto/hook.h>
#include <qproto/host.h>
#include <qproto/logger.h>

#include <authum/host.h>
#include <authum/null.h>

authum_host_t g_qproto_host;

authum_bool_t
qproto_authum_start(authum_host_t *host)
{
	const authum_char_t *mod_dir;

	if (authum_null_eq(host))
		return authum_bool_false;

	g_qproto_host = *host;

	/* Host sink only until cfg loads LoggingMode. */
	authum_logger_init(&g_qproto_logger, &g_qproto_host, authum_logger_sink_host, "qproto");

	if (authum_null_eq(authum_host_crypto(&g_qproto_host))) {
		authum_logger_error(&g_qproto_logger, "host crypto missing (authum_host_crypto)");
		return authum_bool_false;
	}
	if (authum_null_eq(authum_host_engine(&g_qproto_host))) {
		authum_logger_error(&g_qproto_logger, "host engine missing (authum_host_engine)");
		return authum_bool_false;
	}
	if (authum_null_eq(authum_host_env(&g_qproto_host))) {
		authum_logger_error(&g_qproto_logger, "host env missing (authum_host_env)");
		return authum_bool_false;
	}

	qproto_config_load();
	qproto_logger_start(&g_qproto_host, g_qproto_config.logging_sinks);

	mod_dir = authum_host_env_module_cstr(&g_qproto_host);
	authum_logger_info(&g_qproto_logger, "Authum module start — module dir: %s",
			   (!authum_null_eq(mod_dir) && mod_dir[0]) ? mod_dir : "(unset)");
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
	authum_host_clear(&g_qproto_host);
}
