#ifndef QPROTO_HOST_CRYPTO_H
#define QPROTO_HOST_CRYPTO_H

#include <authum/crypto.h>
#include <authum/host.h>

void qproto_host_crypto_bind(const authum_host_t *host);

/** Non-null host crypto ops, or null if unbound / missing. */
const authum_crypto_t *qproto_host_crypto(void);

/** 1 if host crypto ops are bound. */
int qproto_host_crypto_ready(void);

#endif /* QPROTO_HOST_CRYPTO_H */
