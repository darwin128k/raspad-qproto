#include <qproto/client/state.h>

#include <authum/cstr.h>
#include <authum/null.h>

#include <string.h>

qproto_client_info_t *g_qproto_clients;
qproto_client_info_t g_qproto_pending;
authum_bool_t g_qproto_pending_valid;

authum_bool_t
qproto_client_state_start(const authum_sandbox_t *sandbox)
{
    g_qproto_pending_valid = authum_bool_false;
    g_qproto_clients =
        authum_sandbox_alloc(sandbox, sizeof(qproto_client_info_t) * QPROTO_MAX_PLAYERS);
    return authum_null_eq(g_qproto_clients) ? authum_bool_false : authum_bool_true;
}

void
qproto_client_state_stop(void)
{
    g_qproto_clients = authum_null;
    g_qproto_pending_valid = authum_bool_false;
}

void
qproto_client_state_set_pending(const qproto_client_info_t *info)
{
    if (authum_null_eq(info))
    {
        return;
    }
    g_qproto_pending = *info;
    g_qproto_pending_valid = authum_bool_true;
}

void
qproto_client_state_drop_pending(void)
{
    g_qproto_pending_valid = authum_bool_false;
}

qproto_client_info_t *
qproto_client_state_slot(authum_i32_t index)
{
    if (authum_null_eq(g_qproto_clients) || index < 1 || index > QPROTO_MAX_PLAYERS)
    {
        return authum_null;
    }
    return &g_qproto_clients[index - 1];
}

qproto_client_info_t *
qproto_client_state_bind(const authum_event_client_t *ev)
{
    qproto_client_info_t *slot;

    if (authum_null_eq(ev))
    {
        return authum_null;
    }
    slot = qproto_client_state_slot(ev->index);
    if (authum_null_eq(slot))
    {
        g_qproto_pending_valid = authum_bool_false;
        return authum_null;
    }
    if (!g_qproto_pending_valid)
    {
        memset(slot, 0, sizeof *slot);
        return authum_null;
    }
    *slot = g_qproto_pending;
    g_qproto_pending_valid = authum_bool_false;
    slot->size = sizeof *slot;
    slot->index = ev->index;
    slot->userid = ev->userid;
    slot->connected_at = ev->unix_time;
    authum_cstr_copy(slot->name, sizeof slot->name, ev->name);
    authum_cstr_copy(slot->auth_id, sizeof slot->auth_id, ev->auth_id);
    return slot;
}

void
qproto_client_state_clear(authum_i32_t index)
{
    qproto_client_info_t *slot = qproto_client_state_slot(index);

    if (!authum_null_eq(slot))
    {
        memset(slot, 0, sizeof *slot);
    }
}

const qproto_client_info_t *
qproto_client_state_get(authum_i32_t index)
{
    const qproto_client_info_t *slot = qproto_client_state_slot(index);

    return (!authum_null_eq(slot) && slot->index != 0) ? slot : authum_null;
}

const qproto_client_info_t *
qproto_client_state_find(const qproto_client_query_t *query)
{
    const qproto_client_info_t *slot;
    authum_i32_t i;

    if (authum_null_eq(query))
    {
        return authum_null;
    }
    if (query->index > 0)
    {
        return qproto_client_state_get(query->index);
    }
    for (i = 1; i <= QPROTO_MAX_PLAYERS; ++i)
    {
        slot = qproto_client_state_get(i);
        if (authum_null_eq(slot))
        {
            continue;
        }
        if (query->userid > 0)
        {
            if (slot->userid == query->userid)
            {
                return slot;
            }
        }
        else if (query->name[0] != '\0' &&
                 authum_cstr_eq(slot->name, query->name, authum_bool_true))
        {
            return slot;
        }
    }
    return authum_null;
}
