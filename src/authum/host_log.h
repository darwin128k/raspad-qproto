#pragma once

#include <authum/host.h>

#ifdef __cplusplus
extern "C" {
#endif

void qproto_host_log_bind(const authum_host_t *host);
void qproto_host_log(int is_error, const char *line);

#ifdef __cplusplus
}
#endif
