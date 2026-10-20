#include "host_log.h"

namespace {

authum_host_log_fn g_host_log = nullptr;

} // namespace

void
qproto_host_log_bind(const authum_host_t *host)
{
	g_host_log = (host && host->log) ? host->log : nullptr;
}

void
qproto_host_log(int is_error, const char *line)
{
	if (g_host_log && line)
		g_host_log(is_error, line);
}
