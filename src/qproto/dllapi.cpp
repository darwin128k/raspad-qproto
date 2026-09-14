// DLL_FUNCTIONS table (engine -> game DLL / metamod plugin chain). This is where
// pfnConnectionlessPacket lives - the one hook qproto actually needs (see
// dproto's decompiled FUN_00025896/FUN_00029a54 and ReHLDS's own
// SV_ConnectClient_internal, both confirmed this session to funnel "connect"
// through here before the engine's own built-in handling runs).
//
// Stage 1 (this file, for now): wire the hook up and pass everything through
// unmodified (MRES_IGNORED) so the skeleton can be verified against the real
// Metamod-P v1.21p37 + HLSDK headers before the real ticket-parsing logic
// (qproto_authorizers.cpp, already ported and unit-tested) gets plugged in.

#include <extdll.h>
#include <dllapi.h>
#include <meta_api.h>
#include "sdk_util.h"
#include "qproto/qproto_client_state.h"

int Qproto_ConnectionlessPacket(const struct netadr_s* net_from, const char* args, char* response_buffer, int* response_buffer_size)
{
	// Unused in the final design (see qproto_hook.cpp - the real interception point is
	// Steam_NotifyClientConnect, not this). Left wired up as a harmless passthrough.
	RETURN_META_VALUE(MRES_IGNORED, 0);
}

// pfnClientConnect/pfnClientDisconnect are standard, publicly-documented Metamod dllapi
// hooks (unlike Steam_NotifyClientConnect, which needed the low-level dlopen/mprotect
// trick in qproto_hook.cpp) - the engine calls these itself through the normal mod-DLL
// chain, no signature scanning needed. Confirmed via Ghidra decompilation of this
// engine's SV_ConnectClient that pfnClientConnect fires synchronously, right after
// Steam_NotifyClientConnect returns and after host_client->edict is linked, within the
// SAME SV_ConnectClient() call - so network_userid (written by our hook) is always
// already final by the time this runs. That ordering is what
// Qproto_ClientState_OnConnect() below relies on to move the pending record staged by
// qproto_hook.cpp into the right client slot.
qboolean Qproto_ClientConnect(edict_t* pEntity, const char* pszName, const char* pszAddress, char szRejectReason[128])
{
	int index = (*g_engfuncs.pfnIndexOfEdict)(pEntity) - 1; // 0-based, matches qproto_api.h's convention

	// All three sourced through documented engine functions rather than any raw offset
	// read - pfnGetPlayerUserId/pfnGetPlayerAuthId both need the edict_t*, which
	// qproto_hook.cpp never has (it only ever sees the lower-level client_t*). Safe to
	// call here: host_client->edict is already linked and network_userid is already
	// final by this point (see the header comment above and qproto_hook.cpp).
	int userid = (*g_engfuncs.pfnGetPlayerUserId)(pEntity);
	const char* authId = (*g_engfuncs.pfnGetPlayerAuthId)(pEntity);
	float now = (*g_engfuncs.pfnTime)();

	Qproto_ClientState_OnConnect(index, userid, authId, now);
	RETURN_META_VALUE(MRES_IGNORED, TRUE);
}

void Qproto_ClientDisconnect(edict_t* pEntity)
{
	int index = (*g_engfuncs.pfnIndexOfEdict)(pEntity) - 1;
	Qproto_ClientState_OnDisconnect(index);
	RETURN_META(MRES_IGNORED);
}

static DLL_FUNCTIONS gFunctionTable = {
	NULL,					// pfnGameInit
	NULL,					// pfnSpawn
	NULL,					// pfnThink
	NULL,					// pfnUse
	NULL,					// pfnTouch
	NULL,					// pfnBlocked
	NULL,					// pfnKeyValue
	NULL,					// pfnSave
	NULL,					// pfnRestore
	NULL,					// pfnSetAbsBox

	NULL,					// pfnSaveWriteFields
	NULL,					// pfnSaveReadFields

	NULL,					// pfnSaveGlobalState
	NULL,					// pfnRestoreGlobalState
	NULL,					// pfnResetGlobalState

	Qproto_ClientConnect,	// pfnClientConnect
	Qproto_ClientDisconnect,	// pfnClientDisconnect
	NULL,					// pfnClientKill
	NULL,					// pfnClientPutInServer
	NULL,					// pfnClientCommand
	NULL,					// pfnClientUserInfoChanged
	NULL,					// pfnServerActivate
	NULL,					// pfnServerDeactivate

	NULL,					// pfnPlayerPreThink
	NULL,					// pfnPlayerPostThink

	NULL,					// pfnStartFrame
	NULL,					// pfnParmsNewLevel
	NULL,					// pfnParmsChangeLevel

	NULL,					// pfnGetGameDescription
	NULL,					// pfnPlayerCustomization

	NULL,					// pfnSpectatorConnect
	NULL,					// pfnSpectatorDisconnect
	NULL,					// pfnSpectatorThink

	NULL,					// pfnSys_Error

	NULL,					// pfnPM_Move
	NULL,					// pfnPM_Init
	NULL,					// pfnPM_FindTextureType

	NULL,					// pfnSetupVisibility
	NULL,					// pfnUpdateClientData
	NULL,					// pfnAddToFullPack
	NULL,					// pfnCreateBaseline
	NULL,					// pfnRegisterEncoders
	NULL,					// pfnGetWeaponData
	NULL,					// pfnCmdStart
	NULL,					// pfnCmdEnd
	Qproto_ConnectionlessPacket,	// pfnConnectionlessPacket
	NULL,					// pfnGetHullBounds
	NULL,					// pfnCreateInstancedBaselines
	NULL,					// pfnInconsistentFile
	NULL,					// pfnAllowLagCompensation
};

C_DLLEXPORT int GetEntityAPI2(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion)
{
	if (!pFunctionTable) {
		LOG_ERROR(PLID, "GetEntityAPI2 called with null pFunctionTable");
		return FALSE;
	}
	else if (*interfaceVersion != INTERFACE_VERSION) {
		LOG_ERROR(PLID, "GetEntityAPI2 version mismatch; requested=%d ours=%d", *interfaceVersion, INTERFACE_VERSION);
		*interfaceVersion = INTERFACE_VERSION;
		return FALSE;
	}
	memcpy(pFunctionTable, &gFunctionTable, sizeof(DLL_FUNCTIONS));
	return TRUE;
}
