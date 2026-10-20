#ifndef QPROTO_HOST_LOG_H
#define QPROTO_HOST_LOG_H

#include <authum/host.h>

void qproto_host_log_bind(const authum_host_t *host);
void qproto_host_log(int is_error, const char *line);

#endif /* QPROTO_HOST_LOG_H */
