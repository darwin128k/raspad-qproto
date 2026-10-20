#pragma once

#include <authum/client.h>

#ifdef __cplusplus
extern "C" {
#endif

authum_bool_t qproto_authum_start(authum_host_t *host);
void qproto_authum_stop(void);

#ifdef __cplusplus
}
#endif
