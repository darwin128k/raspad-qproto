#pragma once

#include <cstdint>
#include <cstddef>
#include "qproto/qproto_shared.h"

// Per-connected-client auth record. Populated when qproto_hook.cpp finishes
// classifying a connect (native Steam or emulated) and consumed once the standard
// Metamod pfnClientConnect dllapi hook (dllapi.cpp) fires for the SAME client - the
// engine always calls that synchronously, immediately after Steam_NotifyClientConnect
// returns, within the same SV_ConnectClient() call (confirmed via Ghidra decompilation
// of this exact engine build - host_client->edict is linked and gpGamedllFuncs'
// ClientConnect is invoked right there, well before netchan setup or "connected=true").
// This record is what backs qproto_api.h - the stable C ABI other Metamod plugins
// dlsym into to ask "what do we know about this client" or "ban this raw auth key".
struct QprotoClientRecord
{
	bool valid = false;
	int userid = 0;				// client_t::userid - what the engine's "kick #N" console command expects, NOT the slot index (see dllapi.cpp: sourced via pfnGetPlayerUserId, not a raw offset read)
	int protocol = 0;
	uint32_t ipAddress = 0;		// USERID_t.clientip's in-memory representation - byte 0 is the first dotted-quad octet; qproto_api.h's qproto_format_ip() handles this correctly, don't reinterpret_cast it yourself
	client_auth_kind authKind = CA_UNKNOWN;
	client_id_kind idKind = CI_UNKNOWN;	// the RESOLVED cid_* outcome (CI_REAL_STEAM, CI_VALVE_BY_IP, ...) - what idtype/steamid actually ended up written, not just which authorizer matched
	uint32_t steamId = 0;		// low 32 bits of USERID_t.m_SteamID (WON-era account id, not a packed 64-bit CSteamID)
	auth_key_kind authKeyKind = AK_OTHER;
	uint8_t authKey[MAX_AUTHKEY_LEN] = {};
	size_t authKeyLen = 0;		// 0 for native Steam clients - they have no raw auth key qproto ever sees
	char authIdString[32] = {};	// e.g. "STEAM_0:1:12345" - straight from the engine's own pfnGetPlayerAuthId, so it's guaranteed to match what shows in-game/logs, never rebuilt by qproto itself
	float connectTime = 0.0f;	// engine pfnTime() at the moment ClientConnect fired
};

// Called by qproto_hook.cpp right before accepting a connection (native or emulated) -
// stashes the classification for Qproto_ClientState_OnConnect() below to pick up.
void Qproto_ClientState_SetPending(const QprotoClientRecord& rec);

// Called from dllapi.cpp's pfnClientConnect hook - moves the pending record (if any)
// into slot `index` (0-based; dllapi.cpp derives it from pfnIndexOfEdict(pEntity)-1),
// filling in the fields only dllapi.cpp can get at (userid/authIdString/connectTime -
// all sourced from documented engine functions that need the edict_t*, which
// qproto_hook.cpp never has - it only ever sees the lower-level client_t*). Clears the
// pending slot either way.
void Qproto_ClientState_OnConnect(int index, int userid, const char* authIdString, float connectTime);

// Called from dllapi.cpp's pfnClientDisconnect hook - clears slot `index`.
void Qproto_ClientState_OnDisconnect(int index);

// Read-only lookup for qproto_api.cpp. Returns nullptr if index is out of range or
// the slot has no record on file.
const QprotoClientRecord* Qproto_ClientState_Get(int index);
