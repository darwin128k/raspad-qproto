#ifndef QPROTO_CLIENT_AUTH_KIND_H
#define QPROTO_CLIENT_AUTH_KIND_H

#include <qproto/shared.h>

/* Short display name of the protocol (`Steam`, `RevEmu2013`, …), never null. */
const char *qproto_client_auth_kind_name(qproto_client_auth_kind_t kind);

#endif /* QPROTO_CLIENT_AUTH_KIND_H */
