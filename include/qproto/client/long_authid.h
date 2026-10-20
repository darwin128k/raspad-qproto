#ifndef QPROTO_CLIENT_LONG_AUTHID_H
#define QPROTO_CLIENT_LONG_AUTHID_H

#include <authum/bool.h>
#include <authum/crypto.h>

#include <qproto/client/info.h>

/*
 * Fill info->long_authid: SHA-256 of the raw auth key (or of
 * auth_kind + steam_id when the client has no key), first 16 bytes.
 */
authum_bool_t qproto_client_long_authid(const authum_crypto_t *crypto, qproto_client_info_t *info);

#endif /* QPROTO_CLIENT_LONG_AUTHID_H */
