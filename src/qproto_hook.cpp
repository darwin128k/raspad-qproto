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
#include <cmath>	// must precede extdll.h: its min/max macros break <limits>/<cmath> if pulled in after

#include <extdll.h>
#include "qproto_hook.h"
#include "qproto_authorizers.h"
#include "qproto_log.h"
#include "qproto_cfg.h"
#include "sdk_util.h"

namespace {

const uintptr_t kNetworkUseridOffset = 0x4a90; // client_t::network_userid, confirmed via DWARF

typedef int (*SteamNotifyClientConnect_t)(void* client, char* authBuf, int len);
typedef char* (*CmdArgv_t)(int);
typedef char* (*InfoValueForKey_t)(char*, char*);

void* g_engineHandle;
void* g_hookTarget;
SteamNotifyClientConnect_t g_real;
CmdArgv_t g_Cmd_Argv;
InfoValueForKey_t g_Info_ValueForKey;
unsigned char g_savedBytes[5];
bool g_installed;

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
// dproto.cfg's cid_RevEmu default (=1, "real STEAM_xx:xx:xx") is what admins on this
// server already tuned for, so match that convention rather than inventing a new one.
const int kAuthIdTypeSteam = 1;

const char* classic_GetAuthorizerName_stub(client_auth_kind kind)
{
	switch (kind) {
		case CA_REVEMU: return "RevEmu";
		case CA_REVEMU_2013: return "RevEmu2013";
		case CA_STEAMCLIENT_2009: return "SC2009";
		case CA_OLD_REVEMU: return "OldRevEmu";
		case CA_UNKNOWN: return "IP-fallback";
		default: return "unknown";
	}
}

int Qproto_Steam_NotifyClientConnect_hook(void* client, char* authBuf, int len)
{
	Qproto_Log("hook fired: client=%p authBuf=%p len=%d", client, (void*)authBuf, len);

	// Debug: dump the connect command's info-string fields too, in case this client's
	// ticket lives there (as text) instead of / in addition to the trailing raw bytes.
	if (g_Cmd_Argv) {
		char* protinfo = g_Cmd_Argv(3);
		char* userinfo = g_Cmd_Argv(4);
		Qproto_Log("Cmd_Argv(3) protinfo = '%s'", protinfo ? protinfo : "(null)");
		Qproto_Log("Cmd_Argv(4) userinfo = '%s'", userinfo ? userinfo : "(null)");
		if (g_Info_ValueForKey && protinfo) {
			char keyCdkey[] = "cdkey";
			char keyRaw[] = "raw";
			char* cdkey = g_Info_ValueForKey(protinfo, keyCdkey);
			char* raw = g_Info_ValueForKey(protinfo, keyRaw);
			Qproto_Log("protinfo cdkey='%s' (len=%d)", cdkey ? cdkey : "", cdkey ? (int)strlen(cdkey) : -1);
			Qproto_Log("protinfo raw='%s' (len=%d)", raw ? raw : "", raw ? (int)strlen(raw) : -1);
		}
	}

	// Call the real engine function first - real Steam clients must be unaffected.
	RestoreBytes(g_hookTarget, g_savedBytes);
	int result = g_real(client, authBuf, len);
	PatchJmp(g_hookTarget, (void*)&Qproto_Steam_NotifyClientConnect_hook, nullptr);

	Qproto_Log("native Steam_NotifyClientConnect returned %d", result);

	if (result) {
		return result; // native Steam validation already succeeded - nothing to do
	}

	uint8_t* base = (uint8_t*)client + kNetworkUseridOffset;
	uint32_t clientIp = *(uint32_t*)(base + 0xc); // already filled in by SV_ConnectClient before this call runs

	authdata_t authdata = {};
	client_auth_kind kind = CA_UNKNOWN;

	if (authBuf && len > 0) {
		Qproto_Log_HexDump("ticket bytes", authBuf, len);
		authdata.authTicket = (const uint8_t*)authBuf;
		authdata.ticketLen = (size_t)len;
		kind = Qproto_Authorize_Client(&authdata, true, true);
	}

	if (kind == CA_UNKNOWN) {
		// No recognizable structured ticket (RevEmu/RevEmu2013/SC2009 all sign their
		// ticket with a "rev" magic - see qproto_authorizers.cpp). This branch accepts
		// *any* client whose real Steam check failed, not specifically RevEmu users -
		// that's an admin policy choice (dproto.cfg has the same idea via
		// cid_NoSteam47/48=4, VALVE_by_IP), not a safe default, so it's config-gated.
		if (!g_qprotoConfig.allowIpFallback) {
			Qproto_Log("no structured ticket and AllowIPFallback=0 in qproto.cfg - keeping native rejection");
			return 0;
		}

		const uint32_t kIpGenKey = 0xA95CE2B9; // matches classic's IPGEN_KEY convention
		authdata.steamId = clientIp ^ kIpGenKey;
		Qproto_Log("no structured ticket - falling back to IP-based id (clientip=%08x -> steamid=%u)",
			clientIp, authdata.steamId);
	}

	*(int32_t*)(base + 0x0) = kAuthIdTypeSteam;
	*(uint64_t*)(base + 0x4) = (uint64_t)authdata.steamId;

	Qproto_Log("emulated auth ok (%s), steamid=%u", classic_GetAuthorizerName_stub(kind), authdata.steamId);

	return 1; // tell SV_ConnectClient the connection is fine after all
}

} // namespace

bool Qproto_Hook_Install()
{
	if (g_installed) return true;

	g_engineHandle = dlopen("engine_i486.so", RTLD_NOW | RTLD_NOLOAD);
	if (!g_engineHandle) {
		Qproto_Log("dlopen(engine_i486.so, RTLD_NOLOAD) FAILED: %s", dlerror());
		return false;
	}
	Qproto_Log("dlopen(engine_i486.so, RTLD_NOLOAD) ok, handle=%p", g_engineHandle);

	dlerror();
	void* sym = dlsym(g_engineHandle, "Steam_NotifyClientConnect");
	if (!sym) {
		Qproto_Log("dlsym(Steam_NotifyClientConnect) FAILED: %s", dlerror());
		return false;
	}

	g_hookTarget = sym;
	g_real = (SteamNotifyClientConnect_t)sym;

	g_Cmd_Argv = (CmdArgv_t)dlsym(g_engineHandle, "Cmd_Argv");
	g_Info_ValueForKey = (InfoValueForKey_t)dlsym(g_engineHandle, "Info_ValueForKey");
	Qproto_Log("Cmd_Argv=%p Info_ValueForKey=%p", (void*)g_Cmd_Argv, (void*)g_Info_ValueForKey);

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
