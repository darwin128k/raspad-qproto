#include "qproto/qproto_client_state.h"
#include "qproto/qproto_log.h"
#include <string.h>

static qproto_client_record g_pending;
static int g_pending_valid;
static qproto_client_record g_clients[MAX_PLAYERS];

void
qproto_client_state_set_pending(const qproto_client_record *rec)
{
	g_pending = *rec;
	g_pending_valid = 1;
}

void
qproto_client_state_on_connect(int index, int userid, const char *auth_id_string, float connect_time)
{
	if (index < 0 || index >= MAX_PLAYERS) {
		g_pending_valid = 0;
		return;
	}

	if (g_pending_valid) {
		g_clients[index] = g_pending;
		g_clients[index].valid = 1;
		g_clients[index].userid = userid;
		g_clients[index].connect_time = connect_time;
		if (auth_id_string) {
			strncpy(g_clients[index].auth_id_string, auth_id_string,
				sizeof(g_clients[index].auth_id_string) - 1);
		}
	} else {
		memset(&g_clients[index], 0, sizeof(g_clients[index]));
	}
	g_pending_valid = 0;
}

void
qproto_client_state_on_disconnect(int index)
{
	if (index < 0 || index >= MAX_PLAYERS)
		return;
	memset(&g_clients[index], 0, sizeof(g_clients[index]));
}

const qproto_client_record *
qproto_client_state_get(int index)
{
	if (index < 0 || index >= MAX_PLAYERS)
		return NULL;
	if (!g_clients[index].valid)
		return NULL;
	return &g_clients[index];
}
