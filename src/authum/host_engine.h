#pragma once

#include <authum/engine.h>
#include <authum/host.h>

#ifdef __cplusplus
extern "C" {
#endif

void qproto_host_engine_bind(const authum_host_t *host);

/** Non-null host engine ops, or null if unbound / missing. */
const authum_engine_t *qproto_host_engine(void);

/** 1 if host engine ops are bound. */
int qproto_host_engine_ready(void);

#ifdef __cplusplus
}
#endif
