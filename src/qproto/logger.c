#include <qproto/logger.h>

#include <qproto/config.h>

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

	if (authum_logger_open_module_file(&g_qproto_logger, g_qproto_config.logging_split, &path))
		authum_logger_info(&g_qproto_logger, "log opened (%s): %s",
				   g_qproto_config.logging_split == authum_logger_file_split_session
					   ? "session"
					   : "full",
				   authum_path_as_cstr(&path));
	else
		authum_logger_error(&g_qproto_logger, "log open FAILED (split=%s)",
				    g_qproto_config.logging_split == authum_logger_file_split_session
					    ? "session"
					    : "full");
}

void
qproto_logger_stop(void)
{
	authum_logger_close(&g_qproto_logger);
}
