#include <qproto/events.h>

#include <qproto/client/long_authid.h>
#include <qproto/client/state.h>
#include <qproto/event.h>
#include <qproto/host.h>
#include <qproto/logger.h>

#include <authum/event/client.h>
#include <authum/host.h>
#include <authum/null.h>

authum_bool_t
qproto_events_start(void)
{
    return (authum_host_subscribe(&g_qproto_host, AUTHUM_EVENT_CLIENT_CONNECT,
                                  qproto_events_on_connect, authum_null) &&
            authum_host_subscribe(&g_qproto_host, AUTHUM_EVENT_CLIENT_DISCONNECT,
                                  qproto_events_on_disconnect, authum_null) &&
            authum_host_subscribe(&g_qproto_host, QPROTO_EVENT_CLIENT_QUERY, qproto_events_on_query,
                                  authum_null))
               ? authum_bool_true
               : authum_bool_false;
}

authum_event_result_t
qproto_events_on_connect(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = (const authum_event_client_t *)payload;
    qproto_client_info_t *info;
    qproto_client_info_t announced;

    (void)name;
    (void)user;
    if (authum_null_eq(ev))
    {
        return authum_event_result_continue;
    }
    /* The event says that a client is connecting. The refusal lives in the
     * hook chain now: it is not a field of the event. */

    info = qproto_client_state_bind(ev);
    if (authum_null_eq(info))
    {
        return authum_event_result_continue;
    }

    qproto_client_long_authid(authum_host_get_crypto(&g_qproto_host), info);
    authum_logger_info(&g_qproto_logger, "client #%d userid=%d name='%s' auth_kind=%d id=%s",
                       (int)info->index, (int)info->userid, info->name, (int)info->auth_kind,
                       info->auth_id);

    announced = *info;
    authum_host_forward(&g_qproto_host, QPROTO_EVENT_CLIENT_AUTHORIZED, &announced);
    return authum_event_result_handled;
}

authum_event_result_t
qproto_events_on_disconnect(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = (const authum_event_client_t *)payload;

    (void)name;
    (void)user;
    if (!authum_null_eq(ev))
    {
        qproto_client_state_clear(ev->index);
    }
    return authum_event_result_continue;
}

authum_event_result_t
qproto_events_on_query(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    qproto_client_query_t *query = (qproto_client_query_t *)payload;
    const qproto_client_info_t *info;

    (void)name;
    (void)user;
    if (authum_null_eq(query) || query->size < sizeof *query)
    {
        return authum_event_result_continue;
    }
    info = qproto_client_state_find(query);
    if (authum_null_eq(info))
    {
        return authum_event_result_continue;
    }
    query->found = authum_bool_true;
    query->info = *info;
    return authum_event_result_handled;
}
