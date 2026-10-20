#include "host_crypto.h"

static const authum_crypto_t *g_crypto = NULL;

void
qproto_host_crypto_bind(const authum_host_t *host)
{
	g_crypto = (host && host->crypto) ? host->crypto : NULL;
}

const authum_crypto_t *
qproto_host_crypto(void)
{
	return g_crypto;
}

int
qproto_host_crypto_ready(void)
{
	return g_crypto ? 1 : 0;
}
