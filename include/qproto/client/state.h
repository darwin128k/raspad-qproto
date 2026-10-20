#ifndef QPROTO_CLIENT_STATE_H
#define QPROTO_CLIENT_STATE_H

#include <authum/bool.h>
#include <authum/event/client.h>
#include <authum/sandbox.h>

#include <qproto/client/info.h>
#include <qproto/event.h>

/*
 * Who is connected and how they authenticated. hook.c stages a pending record
 * while the engine is still inside SV_ConnectClient; Authum's
 * authum.client.connect (fired from the same call) binds it to the slot.
 *
 * The table lives in qproto's Authum sandbox: nothing to free on stop.
 */

authum_bool_t qproto_client_state_start(const authum_sandbox_t *sandbox);
void qproto_client_state_stop(void);

void qproto_client_state_set_pending(const qproto_client_info_t *info);
void qproto_client_state_drop_pending(void);

/* Move the pending record into ev->index. Null when nothing was pending. */
qproto_client_info_t *qproto_client_state_bind(const authum_event_client_t *ev);

/* Raw slot for @p index (empty or not), null when out of range / not started. */
qproto_client_info_t *qproto_client_state_slot(authum_i32_t index);

void qproto_client_state_clear(authum_i32_t index);

/* Slot @p index (1 … QPROTO_MAX_PLAYERS), or null when empty. */
const qproto_client_info_t *qproto_client_state_get(authum_i32_t index);

/* Lookup by the query's in-fields (index, else userid, else name). */
const qproto_client_info_t *qproto_client_state_find(const qproto_client_query_t *query);

#endif /* QPROTO_CLIENT_STATE_H */
