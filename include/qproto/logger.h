#ifndef QPROTO_LOGGER_H
#define QPROTO_LOGGER_H

#include <authum/logger.h>

/* Module-owned Authum logger. LoggingMode cfg bits == authum_logger_sink_*. */
extern authum_logger_t g_qproto_logger;

void
qproto_logger_start(const authum_host_t *host, authum_logger_sink_t sinks);
void
qproto_logger_stop(void);

#endif /* QPROTO_LOGGER_H */
