#include "host_log.h"

static authum_host_log_fn g_host_log = NULL;

void
qproto_host_log_bind(const authum_host_t *host)
{
	g_host_log = (host && host->log) ? host->log : NULL;
}

void
qproto_host_log(int is_error, const char *line)
{
	if (g_host_log && line)
		g_host_log(is_error, line);
}
