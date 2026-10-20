#ifndef QPROTO_BRIDGE_H
#define QPROTO_BRIDGE_H

#include <authum/client.h>

authum_bool_t
qproto_authum_start(authum_host_t *host);
void
qproto_authum_stop(void);

#endif /* QPROTO_BRIDGE_H */
