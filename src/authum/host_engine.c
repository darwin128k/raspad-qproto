#include "host_engine.h"

static const authum_engine_t *g_engine = NULL;

void
qproto_host_engine_bind(const authum_host_t *host)
{
	g_engine = (host && host->engine) ? host->engine : NULL;
}

const authum_engine_t *
qproto_host_engine(void)
{
	return g_engine;
}

int
qproto_host_engine_ready(void)
{
	return g_engine ? 1 : 0;
}
