#include "bridge.h"
#include "host_log.h"

#include <cmath> /* before extdll.h — HLSDK min/max macros vs C++ */
#include <extdll.h>
#include <enginecallback.h>

#include "qproto/qproto_bans.h"
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_data_dir.h"
#include "qproto/qproto_hook.h"
#include "qproto/qproto_log.h"

#include <cstring>

extern enginefuncs_t g_engfuncs;
extern globalvars_t *gpGlobals;

namespace {

bool
bind_engine_from_host(const authum_host_t *host)
{
	if (!host || !host->engine_funcs || !host->globals)
		return false;

	auto *ef = static_cast<enginefuncs_t *>(host->engine_funcs());
	auto *gv = static_cast<globalvars_t *>(host->globals());
	if (!ef || !gv)
		return false;

	std::memcpy(&g_engfuncs, ef, sizeof(g_engfuncs));
	gpGlobals = gv;
	return true;
}

} // namespace

authum_bool_t
qproto_authum_start(authum_host_t *host)
{
	if (!host)
		return AUTHUM_FALSE;

	if (!bind_engine_from_host(host))
		return AUTHUM_FALSE;

	qproto_host_log_bind(host);
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
	qproto_host_log_bind(nullptr);
}
