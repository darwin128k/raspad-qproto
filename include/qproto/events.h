#ifndef QPROTO_EVENTS_H
#define QPROTO_EVENTS_H

#include <authum/bool.h>
#include <authum/char.h>
#include <authum/event/result.h>
#include <authum/ptr.h>

/*
 * qproto's side of the Authum bus: binds auth records on
 * authum.client.connect, clears them on authum.client.disconnect, answers
 * qproto.client.query and announces qproto.client.authorized.
 */

authum_bool_t qproto_events_start(void);

authum_event_result_t qproto_events_on_connect(const authum_char_t *name, authum_ptr payload,
					       authum_ptr user);
authum_event_result_t qproto_events_on_disconnect(const authum_char_t *name, authum_ptr payload,
						  authum_ptr user);
authum_event_result_t qproto_events_on_query(const authum_char_t *name, authum_ptr payload,
					     authum_ptr user);

#endif /* QPROTO_EVENTS_H */
