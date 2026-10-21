// The one hook qproto needs. Confirmed this session via Ghidra + the binary's own
// DWARF debug info (engine_i486.so, Aug 2018 build):
//
//   SV_ConnectClient(): for protocol==3 (Steam) connects:
//     qVar12 = Steam_NotifyClientConnect(client, authBuf, len);
//     if (!qVar12) { if (!sv_lan) { SV_RejectConnection(...); return; } ... }
//
//   struct client_t {
//     ...
//     +0x4a8c  int      userid;
//     +0x4a90  USERID_t network_userid;   // { int idtype; uint64 m_SteamID; uint clientip; }
//     +0x4aa0  char     userinfo[256];
//     ...
//   };
//
// So: call the real Steam_NotifyClientConnect first (real Steam clients must keep
// working exactly as before). Only when it fails do we try qproto_authorizers.cpp
// on the same raw ticket bytes; on success we write directly into the client's
// network_userid and tell SV_ConnectClient the connection is fine after all -
// everything downstream (SV_GetIDString, logs, ban checks) reads that same field,
// so nothing else needs patching.
//
// Patch mechanism (mprotect + 5-byte JMP at the function's entry point, save/restore
// original bytes to call through) is exactly what was verified end-to-end against
// this real binary in hook_selftest.cpp - reused verbatim here.

#include <dlfcn.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>	// must precede extdll.h: its min/max macros break <limits>/<cmath> if pulled in after

#include <extdll.h>
#include "qproto/qproto_hook.h"
#include "qproto/qproto_authorizers.h"
#include "qproto/qproto_log.h"
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_bans.h"
#include "qproto/qproto_client_state.h"
#include "qproto/qproto_engine.h"
#include "sdk_util.h"
#include <cstdio>

namespace {

typedef int (*SteamNotifyClientConnect_t)(void* client, char* authBuf, int len);
typedef char* (*CmdArgv_t)(int);
typedef char* (*InfoValueForKey_t)(char*, char*);

void* g_hookTarget;
SteamNotifyClientConnect_t g_real;
CmdArgv_t g_Cmd_Argv;
InfoValueForKey_t g_Info_ValueForKey;
unsigned char g_savedBytes[5];
bool g_installed;
uintptr_t g_networkUseridOffset = 0x4a90;
uintptr_t g_remoteAddressOffset = 0x20;


void PatchJmp(void* target, void* dest, unsigned char* saveBack)
{
	uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
	size_t len = ((uintptr_t)target + 5) - page;
	mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);

	if (saveBack) memcpy(saveBack, target, 5);

	unsigned char* t = (unsigned char*)target;
	int32_t rel = (int32_t)((uintptr_t)dest - (uintptr_t)target - 5);
	t[0] = 0xE9;
	memcpy(t + 1, &rel, 4);
}

void RestoreBytes(void* target, const unsigned char* saved)
{
	uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
	size_t len = ((uintptr_t)target + 5) - page;
	mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy(target, saved, 5);
}

// AUTH_IDTYPE from engine's userid.h: STEAM=1, VALVE=2, LOCAL=3.
enum { AUTH_IDTYPE_STEAM = 1, AUTH_IDTYPE_VALVE = 2, AUTH_IDTYPE_LOCAL = 3 };

// Maps a dproto.cfg-style cid_* value (client_id_kind, qproto_shared.h) to what the
// engine's own SV_GetIDString can actually render for us, since we write into
// client_t::network_userid and let the *unmodified* engine format the final string
// (see file header) rather than building "STEAM_x:y:z" ourselves the way classic plugins
// does with full ReHLDS hook access. SV_GetIDString only branches on idtype 1/2/3 -
// everything CI_*_STEAM-ish collapses to STEAM, everything CI_*_VALVE-ish to VALVE
// (the LAN/PENDING sub-strings then come for free from the engine's own sv_lan and
// zero-steamid checks). CI_DEPRECATED means "reject", matching dproto.cfg exactly.
int MapClientIdKindToAuthIdType(client_id_kind cid)
{
	switch (cid) {
		case CI_REAL_STEAM:
		case CI_STEAM_BY_IP:
		case CI_STEAM_ID_LAN:
		case CI_STEAM_ID_PENDING:
		case CI_STEAM_666_88_666:
			return AUTH_IDTYPE_STEAM;

		case CI_REAL_VALVE:
		case CI_VALVE_BY_IP:
		case CI_VALVE_ID_LAN:
		case CI_VALVE_ID_PENDING:
			return AUTH_IDTYPE_VALVE;

		case CI_HLTV:
			return AUTH_IDTYPE_LOCAL;

		case CI_DEPRECATED:
			return -1; // reject

		default: // CI_UNKNOWN, CI_RESERVED, CI_MAX - no sane rendering, be safe and reject
			return -1;
	}
}

client_id_kind CidForAuthKind(client_auth_kind kind)
{
	switch (kind) {
		case CA_REVEMU: return g_qprotoConfig.cidRevEmu;
		case CA_REVEMU_2013: return g_qprotoConfig.cidRevEmu2013;
		case CA_STEAMCLIENT_2009: return g_qprotoConfig.cidSC2009;
		case CA_OLD_REVEMU: return g_qprotoConfig.cidOldRevEmu;
		case CA_SETTI: return g_qprotoConfig.cidSetti;
		case CA_NO_STEAM_47: return g_qprotoConfig.cidNoSteam47;
		case CA_NO_STEAM_48: return g_qprotoConfig.cidNoSteam48;
		case CA_STEAM_PENDING: return g_qprotoConfig.cidSteamPending;
		case CA_SXEI: return g_qprotoConfig.cidSXEI;
		case CA_VELLUM: return g_qprotoConfig.cidVellum;
		case CA_STEAM: return g_qprotoConfig.cidSteam;
		default: return CI_UNKNOWN;
	}
}

// Mirrors classic utils.cpp IsNumericAuthKind(), trimmed to what qproto can
// actually produce - Setti/NoSteam47/NoSteam48 are deliberately excluded there too
// (they're fixed-identity kinds, not "this steamid might just be unresolved yet").
// CA_STEAM is included, matching classic HLDS auth exactly - even a native Steam auth can in
// principle resolve to a pending id.
bool IsNumericAuthKind(client_auth_kind kind)
{
	switch (kind) {
		case CA_OLD_REVEMU: case CA_REVEMU: case CA_STEAMCLIENT_2009: case CA_REVEMU_2013:
		case CA_SXEI: case CA_VELLUM: case CA_STEAM:
			return true;
		default:
			return false;
	}
}

const char* Qproto_GetAuthorizerName(client_auth_kind kind)
{
	switch (kind) {
		case CA_REVEMU: return "RevEmu";
		case CA_REVEMU_2013: return "RevEmu2013";
		case CA_STEAMCLIENT_2009: return "SC2009";
		case CA_OLD_REVEMU: return "OldRevEmu";
		case CA_SETTI: return "Setti";
		case CA_NO_STEAM_47: return "NoSteam47";
		case CA_NO_STEAM_48: return "NoSteam48";
		case CA_STEAM_PENDING: return "Steam_PENDING";
		case CA_SXEI: return "sXe";
		case CA_VELLUM: return "Vellum";
		case CA_STEAM: return "Steam";
		default: return "unknown";
	}
}


int Qproto_Steam_NotifyClientConnect_hook(void* client, char* authBuf, int len)
{
	Qproto_Log("hook fired: client=%p authBuf=%p len=%d", client, (void*)authBuf, len);

	// protocol/sxeiHidHex come from the connect command's info-strings, not the ticket -
	// needed below by NoSteam47Authorize/NoSteam48Authorize/SXEIAuthorize
	// (qproto_authorizers.cpp), from classic HLDS auth SV_CheckKeyInfo_hook ("prot" key)
	// and SXEI authorizer ("*HID" key). Extracted once, before the native call (these
	// come from Cmd_Argv/Info_ValueForKey, unaffected by the Steam_NotifyClientConnect patch).
	int protocol = 0;
	const char* sxeiHidHex = nullptr;
	if (g_Cmd_Argv) {
		char* protinfo = g_Cmd_Argv(3);
		char* userinfo = g_Cmd_Argv(4);
		Qproto_Log("Cmd_Argv(3) protinfo = '%s'", protinfo ? protinfo : "(null)");
		Qproto_Log("Cmd_Argv(4) userinfo = '%s'", userinfo ? userinfo : "(null)");
		if (g_Info_ValueForKey && protinfo) {
			char keyCdkey[] = "cdkey";
			char keyRaw[] = "raw";
			char keyProt[] = "prot";
			char* cdkey = g_Info_ValueForKey(protinfo, keyCdkey);
			char* raw = g_Info_ValueForKey(protinfo, keyRaw);
			char* prot = g_Info_ValueForKey(protinfo, keyProt);
			Qproto_Log("protinfo cdkey='%s' (len=%d)", cdkey ? cdkey : "", cdkey ? (int)strlen(cdkey) : -1);
			Qproto_Log("protinfo raw='%s' (len=%d)", raw ? raw : "", raw ? (int)strlen(raw) : -1);
			protocol = prot ? atoi(prot) : 0;
		}
		if (g_Info_ValueForKey && userinfo) {
			char keyHid[] = "*HID";
			sxeiHidHex = g_Info_ValueForKey(userinfo, keyHid);
		}
	}

	// Call the real engine function first - real Steam clients must be unaffected.
	RestoreBytes(g_hookTarget, g_savedBytes);
	int result = g_real(client, authBuf, len);
	PatchJmp(g_hookTarget, (void*)&Qproto_Steam_NotifyClientConnect_hook, nullptr);

	Qproto_Log("native Steam_NotifyClientConnect returned %d", result);

	uint8_t* base = (uint8_t*)client + g_networkUseridOffset;
	uint32_t clientIp = *(uint32_t*)(base + 0xc); // already filled in by SV_ConnectClient before this call runs

	if (result) {
		// Real/native Steam auth succeeded. Classic auth still runs this through the same
		// cid_* pipeline as every emulator (client_auth.cpp: authkind=CA_STEAM, then the
		// idkind switch applies uniformly) instead of passing it through unconditionally -
		// e.g. cid_Steam=3/4 can mask even a real Steam player behind an IP-derived id.
		// cid_Steam is clamped at config-load time (qproto_cfg.cpp) to only the values
		// enforced below, so there's no "requested but unsupported" case to handle here.
		uint32_t nativeSteamId = (uint32_t)(*(uint64_t*)(base + 0x4) & 0xFFFFFFFFu);
		client_auth_kind kind = (nativeSteamId <= STEAM_ID_PENDING) ? CA_STEAM_PENDING : CA_STEAM;
		client_id_kind cid = CidForAuthKind(kind);
		uint32_t finalSteamId = nativeSteamId;

		if (cid == CI_STEAM_BY_IP || cid == CI_VALVE_BY_IP) {
			int authIdType = MapClientIdKindToAuthIdType(cid);
			finalSteamId = clientIp ^ IPGEN_KEY;
			*(int32_t*)(base + 0x0) = authIdType;
			*(uint64_t*)(base + 0x4) = (uint64_t)finalSteamId;
			Qproto_Log("native Steam auth ok (%s), cid=%d overrides id -> idtype=%d steamid=%u",
				Qproto_GetAuthorizerName(kind), (int)cid, authIdType, finalSteamId);
		}
		else {
			Qproto_Log("native Steam auth ok (%s), cid=%d - no override configured", Qproto_GetAuthorizerName(kind), (int)cid);
		}

		// Stage this classification for dllapi.cpp's pfnClientConnect hook to pick up -
		// see qproto_client_state.h. Native Steam clients have no raw auth key, so
		// authKeyLen stays 0 (the default) - qproto_api.h callers treat that as "no
		// hardware-id ban is possible for this client", same as a real admin would need
		// Steam's own tools for that.
		QprotoClientRecord rec;
		rec.protocol = protocol;
		rec.ipAddress = clientIp;
		rec.authKind = kind;
		rec.idKind = cid;
		rec.steamId = finalSteamId;
		Qproto_ClientState_SetPending(rec);

		return result;
	}

	authdata_t authdata = {};
	authdata.authTicket = (const uint8_t*)authBuf;
	authdata.ticketLen = (size_t)(authBuf ? len : 0);
	authdata.protocol = protocol;
	authdata.sxeiHidHex = sxeiHidHex;

	if (authBuf && len > 0) {
		Qproto_Log_HexDump("ticket bytes", authBuf, len);
	}

	client_auth_kind kind = Qproto_Authorize_Client(&authdata, true, true);

	if (kind == CA_UNKNOWN) {
		/* Native already returned 0 — do not call SV_RejectConnection again
		 * (second reject on a dead netchan crashes HLDS). */
		Qproto_Log("no authorizer matched (protocol=%d, ticketLen=%d) - keeping native rejection",
			authdata.protocol, (int)authdata.ticketLen);
		return 0;
	}

	if (authdata.authKeyLen > 0) {
		char hex[MAX_AUTHKEY_LEN * 2 + 1];
		for (size_t i = 0; i < authdata.authKeyLen; i++) {
			snprintf(hex + i * 2, 3, "%02x", (uint8_t)authdata.authKey[i]);
		}
		Qproto_Log("raw auth key (%s, hex - qproto_ban_authkey()/qproto_bans.cfg use this exact string): %s",
			Qproto_GetAuthorizerName(kind), hex);

		if (Qproto_Bans_IsBanned((const uint8_t*)authdata.authKey, authdata.authKeyLen)) {
			/* Native already rejected — no second SV_RejectConnection (HLDS crash). */
			Qproto_Log("REJECTED: raw auth key is on the qproto_bans.cfg ban list - keeping native rejection");
			return 0;
		}
	}

	// Reclassify to CA_STEAM_PENDING when the resolved steamId came back as
	// STEAM_ID_LAN(0)/STEAM_ID_PENDING(1) - i.e. the client's HDD serial/volume ID
	// wasn't available - so it gets its own cid_SteamPending rule instead of the
	// per-emulator one. Mirrors classic client_auth.cpp IsNumericAuthKind()+IsValidId()
	// check; HLTV/Setti/NoSteam47/48 are excluded on purpose (see IsNumericAuthKind above).
	if (IsNumericAuthKind(kind) && authdata.steamId <= STEAM_ID_PENDING) {
		kind = CA_STEAM_PENDING;
	}

	client_id_kind cid = CidForAuthKind(kind);
	int authIdType = MapClientIdKindToAuthIdType(cid);
	if (authIdType < 0) {
		/* Same as unknown: native already rejected — no second SV_RejectConnection. */
		Qproto_Log("%s authorized but cid=%d (dproto.cfg-style) means reject - keeping native rejection",
			Qproto_GetAuthorizerName(kind), (int)cid);
		return 0;
	}

	// CI_STEAM_BY_IP/CI_VALVE_BY_IP override whatever steamId the authorizer computed
	// and derive a fresh one from the client's IP instead - mirrors classic // client_auth.cpp SteamByIp() switch on the *resolved* idkind (applies regardless
	// of which authorizer produced the classification).
	uint32_t finalSteamId = authdata.steamId;
	if (cid == CI_STEAM_BY_IP || cid == CI_VALVE_BY_IP) {
		finalSteamId = clientIp ^ IPGEN_KEY;
	}

	*(int32_t*)(base + 0x0) = authIdType;
	*(uint64_t*)(base + 0x4) = (uint64_t)finalSteamId;

	Qproto_Log("emulated auth ok (%s), cid=%d -> idtype=%d, steamid=%u",
		Qproto_GetAuthorizerName(kind), (int)cid, authIdType, finalSteamId);

	// Stage this classification for dllapi.cpp's pfnClientConnect hook to pick up -
	// see qproto_client_state.h.
	QprotoClientRecord rec;
	rec.protocol = protocol;
	rec.ipAddress = clientIp;
	rec.authKind = kind;
	rec.idKind = cid;
	rec.steamId = finalSteamId;
	rec.authKeyKind = authdata.authKeyKind;
	rec.authKeyLen = authdata.authKeyLen;
	if (authdata.authKeyLen > 0) {
		memcpy(rec.authKey, authdata.authKey, authdata.authKeyLen);
	}
	Qproto_ClientState_SetPending(rec);

	return 1; // tell SV_ConnectClient the connection is fine after all
}

} // namespace

bool Qproto_Hook_Install()
{
	if (g_installed) return true;

	bool viaDynsym = false;
	void* sym = Qproto_Engine_Resolve("Steam_NotifyClientConnect", &viaDynsym);
	if (!sym) {
		Qproto_Log("resolve(Steam_NotifyClientConnect) FAILED");
		return false;
	}

	const QprotoEngineLayoutInfo& layout =
		Qproto_Engine_SelectLayout(g_qprotoConfig.engineLayout, viaDynsym);
	g_networkUseridOffset = layout.networkUseridOffset;
	g_remoteAddressOffset = layout.remoteAddressOffset;
	Qproto_Log("engine layout: %s (override=%s, viaDynsym=%d) network_userid=+0x%lx remote_address=+0x%lx",
		layout.name,
		Qproto_Engine_LayoutName(g_qprotoConfig.engineLayout),
		(int)viaDynsym,
		(unsigned long)g_networkUseridOffset,
		(unsigned long)g_remoteAddressOffset);

	g_hookTarget = sym;
	g_real = (SteamNotifyClientConnect_t)sym;

	g_Cmd_Argv = (CmdArgv_t)Qproto_Engine_Resolve("Cmd_Argv", nullptr);
	g_Info_ValueForKey = (InfoValueForKey_t)Qproto_Engine_Resolve("Info_ValueForKey", nullptr);
	Qproto_Log("Cmd_Argv=%p Info_ValueForKey=%p",
		(void*)g_Cmd_Argv, (void*)g_Info_ValueForKey);

	PatchJmp(g_hookTarget, (void*)&Qproto_Steam_NotifyClientConnect_hook, g_savedBytes);
	g_installed = true;
	Qproto_Log("hook installed on Steam_NotifyClientConnect @ %p", g_hookTarget);
	return true;
}

void Qproto_Hook_Remove()
{
	if (!g_installed) return;
	RestoreBytes(g_hookTarget, g_savedBytes);
	g_installed = false;
	Qproto_Log("hook removed, original bytes restored");
}
