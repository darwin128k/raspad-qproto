#include "qproto/qproto_client_state.h"
#include "qproto/qproto_log.h"
#include <cstring>

namespace {
qproto_client_record g_pending;
bool g_pendingValid;
qproto_client_record g_clients[MAX_PLAYERS];
} // namespace

void qproto_client_state_set_pending(const qproto_client_record& rec)
{
	g_pending = rec;
	g_pendingValid = true;
}

void qproto_client_state_on_connect(int index, int userid, const char* authIdString, float connectTime)
{
	if (index < 0 || index >= MAX_PLAYERS) {
		g_pendingValid = false; // don't let a stale record leak into a later, unrelated connect
		return;
	}

	if (g_pendingValid) {
		g_clients[index] = g_pending;
		g_clients[index].valid = true;
		g_clients[index].userid = userid;
		g_clients[index].connectTime = connectTime;
		if (authIdString) {
			strncpy(g_clients[index].authIdString, authIdString, sizeof(g_clients[index].authIdString) - 1);
		}
	}
	else {
		// pfnClientConnect fired without a preceding Steam_NotifyClientConnect hook
		// having staged anything for it - shouldn't normally happen (would mean a
		// connect path we don't know about, e.g. an HLTV proxy - see qproto_shared.h's
		// comment on CA_HLTV's removal). Clear rather than keep stale data from a
		// previous occupant of this slot.
		g_clients[index] = qproto_client_record{};
	}
	g_pendingValid = false;
}

void qproto_client_state_on_disconnect(int index)
{
	if (index < 0 || index >= MAX_PLAYERS) return;
	g_clients[index] = qproto_client_record{};
}

const qproto_client_record* qproto_client_state_get(int index)
{
	if (index < 0 || index >= MAX_PLAYERS) return nullptr;
	if (!g_clients[index].valid) return nullptr;
	return &g_clients[index];
}
