#ifndef QPROTO_HOST_ENGINE_H
#define QPROTO_HOST_ENGINE_H

#include <authum/engine.h>
#include <authum/host.h>

void qproto_host_engine_bind(const authum_host_t *host);

/** Non-null host engine ops, or null if unbound / missing. */
const authum_engine_t *qproto_host_engine(void);

/** 1 if host engine ops are bound. */
int qproto_host_engine_ready(void);

#endif /* QPROTO_HOST_ENGINE_H */
