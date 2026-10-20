#include "bridge.h"
#include "host_crypto.h"
#include "host_engine.h"
#include "host_log.h"

#include "qproto/qproto_bans.h"
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_data_dir.h"
#include "qproto/qproto_hook.h"
#include "qproto/qproto_log.h"

authum_bool_t
qproto_authum_start(authum_host_t *host)
{
	if (!host)
		return AUTHUM_FALSE;

	qproto_host_log_bind(host);
	qproto_host_crypto_bind(host);
	qproto_host_engine_bind(host);

	if (!qproto_host_crypto_ready()) {
		qproto_host_log(1, "qproto: host crypto missing (authum_host_t.crypto)");
		return AUTHUM_FALSE;
	}
	if (!qproto_host_engine_ready()) {
		qproto_host_log(1, "qproto: host engine missing (authum_host_t.engine)");
		return AUTHUM_FALSE;
	}

	if (host->module_dir && host->module_dir[0])
		qproto_set_data_dir(host->module_dir);

	qproto_log_init(g_qproto_config.loggingMode);
	qproto_cfg_load();
	if (g_qproto_config.loggingMode != 0) {
		qproto_log_close();
		qproto_log_init(g_qproto_config.loggingMode);
	}

	qproto_log("Authum module start — data dir: %s",
		qproto_get_data_dir() ? qproto_get_data_dir() : "(unset)");
	qproto_log("qproto 2.0.0 under Authum ABI 0.2 — installing Steam_NotifyClientConnect hook");

	qproto_bans_load();

	if (!qproto_hook_install()) {
		qproto_log("qproto_hook_install FAILED");
		qproto_log_close();
		return AUTHUM_FALSE;
	}
	qproto_log("hook installed OK");
	return AUTHUM_TRUE;
}

void
qproto_authum_stop(void)
{
	qproto_hook_remove();
	qproto_log("Authum module stop — hook removed");
	qproto_log_close();
	qproto_host_engine_bind(nullptr);
	qproto_host_crypto_bind(nullptr);
	qproto_host_log_bind(nullptr);
}
