#ifndef QPROTO_LOGGER_H
#define QPROTO_LOGGER_H

#include <authum/logger.h>

/*
 * Module-owned Authum logger. Where lines go (logs/qproto/, authum.log, the
 * console) and at which level is set in addons/authum/authum.cfg, not here.
 */
extern authum_logger_t g_qproto_logger;

void
qproto_logger_start(const authum_host_t *host);
void
qproto_logger_stop(void);

#endif /* QPROTO_LOGGER_H */
