#include <qproto/logger.h>

#include <authum/host.h>
#include <authum/path.h>

authum_logger_t g_qproto_logger;

void
qproto_logger_start(const authum_host_t *host, authum_logger_sink_t sinks)
{
	authum_path_t path;

	authum_logger_close(&g_qproto_logger);
	authum_logger_init(&g_qproto_logger, host, sinks, "qproto");

	if ((sinks & authum_logger_sink_file) == 0u)
		return;

	if (!authum_path_join(&path, authum_host_env_module(host), "qproto.log")) {
		authum_logger_error(&g_qproto_logger, "qproto.log: no module dir in host env");
		return;
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
