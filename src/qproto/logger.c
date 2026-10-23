#include <qproto/logger.h>

#include <authum/host.h>

authum_logger_t g_qproto_logger;

void
qproto_logger_start(const authum_host_t *host)
{
    authum_logger_close(&g_qproto_logger);
    authum_logger_init(&g_qproto_logger, host);
}

void
qproto_logger_stop(void)
{
    authum_logger_close(&g_qproto_logger);
}
