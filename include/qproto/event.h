#ifndef QPROTO_EVENT_H
#define QPROTO_EVENT_H

/*
 * qproto's public contract on the Authum event bus. Other modules include
 * this header (types only) and talk to qproto through <authum/events.h>:
 *
 *   QPROTO_EVENT_CLIENT_AUTHORIZED  forward  payload qproto_client_info_t
 *       Published once per connect, right after Authum's
 *       authum.client.connect, when qproto knows how the client got in.
 *
 *   QPROTO_EVENT_CLIENT_QUERY       query    payload qproto_client_query_t
 *       Fill the in-fields and ask with `authum_host_query`; qproto answers
 *       with `found` + `info` and returns authum_event_result_handled. Result
 *       continue → qproto is not loaded or nobody matched.
 */

#include <authum/bool.h>
#include <authum/char.h>
#include <authum/size.h>

#include <qproto/client/info.h>

#define QPROTO_EVENT_CLIENT_AUTHORIZED "qproto.client.authorized"
#define QPROTO_EVENT_CLIENT_QUERY "qproto.client.query"

/*
 * Look a client up by the first in-field that is set:
 * index (> 0), else userid (> 0), else name (non-empty, connect name,
 * case-insensitive).
 */
struct qproto_client_query
{
    /* sizeof(qproto_client_query_t) as built by the caller. */
    authum_usize_t size;

    /* in */
    authum_i32_t index;
    authum_i32_t userid;
    authum_char_t name[qproto_client_name_max];

    /* out */
    authum_bool_t found;
    qproto_client_info_t info;
};
typedef struct qproto_client_query qproto_client_query_t;

#endif /* QPROTO_EVENT_H */
