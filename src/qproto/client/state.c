#include <qproto/client/state.h>



#include <authum/null.h>

#include <string.h>



static qproto_client_record_t g_pending;

static authum_bool_t g_pending_valid = authum_bool_false;

static qproto_client_record_t g_clients[QPROTO_MAX_PLAYERS];



void

qproto_client_state_set_pending(const qproto_client_record_t *rec)

{

	g_pending = *rec;

	g_pending_valid = authum_bool_true;

}



void

qproto_client_state_on_connect(authum_i32_t index, authum_i32_t userid,

			       const authum_char_t *auth_id_string, float connect_time)

{

	if (index < 0 || index >= QPROTO_MAX_PLAYERS) {

		g_pending_valid = authum_bool_false;

		return;

	}



	if (g_pending_valid) {

		g_clients[index] = g_pending;

		g_clients[index].valid = authum_bool_true;

		g_clients[index].userid = userid;

		g_clients[index].connect_time = connect_time;

		if (!authum_null_eq(auth_id_string)) {

			strncpy(g_clients[index].auth_id_string, auth_id_string,

				sizeof(g_clients[index].auth_id_string) - 1u);

		}

	} else {

		memset(&g_clients[index], 0, sizeof(g_clients[index]));

	}

	g_pending_valid = authum_bool_false;

}



void

qproto_client_state_on_disconnect(authum_i32_t index)

{

	if (index < 0 || index >= QPROTO_MAX_PLAYERS)

		return;

	memset(&g_clients[index], 0, sizeof(g_clients[index]));

}



const qproto_client_record_t *

qproto_client_state_get(authum_i32_t index)

{

	if (index < 0 || index >= QPROTO_MAX_PLAYERS)

		return authum_null;

	if (!g_clients[index].valid)

		return authum_null;

	return &g_clients[index];

}

