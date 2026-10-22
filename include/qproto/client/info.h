#ifndef QPROTO_CLIENT_INFO_H
#define QPROTO_CLIENT_INFO_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

#include <qproto/shared.h>

enum
{
    qproto_client_long_authid_size = 16,
    qproto_client_name_max = 32,
    qproto_client_auth_id_max = 64
};

/*
 * What qproto knows about one connected client: how it authenticated. This is
 * the payload of QPROTO_EVENT_CLIENT_AUTHORIZED and the answer inside
 * qproto_client_query_t. Header-only: other modules include it, they never
 * link qproto.
 *
 * Who-entered-when history, bans, stats: not here — those are other modules
 * listening to the same events.
 */
struct qproto_client_info
{
    /* sizeof(qproto_client_info_t) as built by qproto. */
    authum_usize_t size;
    /* Entity index 1 … maxClients (0 → slot empty). */
    authum_i32_t index;
    /* Engine userid (`kick #userid`). */
    authum_i32_t userid;
    /* Net protocol from the connect string (47 / 48). */
    authum_i32_t protocol;
    /* The protocol / emulator the client authenticated with. */
    qproto_client_auth_kind_t auth_kind;
    /* cid_* outcome: which kind of id the engine got. */
    qproto_client_id_kind_t id_kind;
    /* Low 32 bits of the engine SteamID after qproto's decision. */
    authum_u32_t steam_id;
    /* USERID_t.clientip as the engine stores it. */
    authum_u32_t ip_address;
    qproto_auth_key_kind_t auth_key_kind;
    /* 0 for native Steam clients. */
    authum_usize_t auth_key_len;
    authum_byte_t auth_key[QPROTO_MAX_AUTHKEY_LEN];
    /* First 16 bytes of SHA-256(auth key) — or of (auth_kind, steam_id) when
     * there is no key. A stable id for ban / stats modules. */
    authum_byte_t long_authid[qproto_client_long_authid_size];
    /* Engine auth id string at connect (`STEAM_0:1:…`). */
    authum_char_t auth_id[qproto_client_auth_id_max];
    /* Name the client connected with (later renames: authum.client.info_changed). */
    authum_char_t name[qproto_client_name_max];
    /* Wall clock at connect, seconds since 1970-01-01 UTC. */
    authum_i64_t connected_at;
};
typedef struct qproto_client_info qproto_client_info_t;

#endif /* QPROTO_CLIENT_INFO_H */
