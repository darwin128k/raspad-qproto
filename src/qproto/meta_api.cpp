// Standard Metamod-P plugin interface (adapted from stub_plugin/meta_api.cpp,
// v1.21p37, matching the exact Metamod build installed on the server).
// v1 only needs GetEntityAPI2 (that's where pfnConnectionlessPacket lives, in
// dllapi.cpp) - no engine_api.cpp hooks are needed for the connect-time auth hook.

#include <extdll.h>
#include <meta_api.h>
#include "sdk_util.h"
#include "qproto/qproto_hook.h"
#include "qproto/qproto_log.h"
#include <cstdio>
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_bans.h"

static META_FUNCTIONS gMetaFunctionTable = {
	NULL,			// pfnGetEntityAPI
	NULL,			// pfnGetEntityAPI_Post
	GetEntityAPI2,	// pfnGetEntityAPI2       <- dllapi.cpp, carries pfnConnectionlessPacket
	NULL,			// pfnGetEntityAPI2_Post
	NULL,			// pfnGetNewDLLFunctions
	NULL,			// pfnGetNewDLLFunctions_Post
	NULL,			// pfnGetEngineFunctions
	NULL,			// pfnGetEngineFunctions_Post
};

plugin_info_t Plugin_info = {
	META_INTERFACE_VERSION,
	"qproto",
	"0.2",
	__DATE__,
	"raspad-server",
	"",
	"QPROTO",
	PT_STARTUP,
	PT_NEVER,
};

meta_globals_t* gpMetaGlobals;
gamedll_funcs_t* gpGamedllFuncs;
mutil_funcs_t* gpMetaUtilFuncs;

C_DLLEXPORT int Meta_Query(char* /*ifvers*/, plugin_info_t** pPlugInfo, mutil_funcs_t* pMetaUtilFuncs)
{
	*pPlugInfo = &Plugin_info;
	gpMetaUtilFuncs = pMetaUtilFuncs;
	return TRUE;
}

C_DLLEXPORT int Meta_Attach(PLUG_LOADTIME /*now*/, META_FUNCTIONS* pFunctionTable, meta_globals_t* pMGlobals, gamedll_funcs_t* pGamedllFuncs)
{
	if (!pMGlobals) {
		LOG_ERROR(PLID, "Meta_Attach called with null pMGlobals");
		return FALSE;
	}
	gpMetaGlobals = pMGlobals;

	if (!pFunctionTable) {
		LOG_ERROR(PLID, "Meta_Attach called with null pFunctionTable");
		return FALSE;
	}
	memcpy(pFunctionTable, &gMetaFunctionTable, sizeof(META_FUNCTIONS));
	gpGamedllFuncs = pGamedllFuncs;

	// Config must be read before the log file is opened - LoggingMode's rl_logfile
	// bit decides whether Qproto_Log_Init() creates qproto.log at all.
	Qproto_Cfg_Load();
	Qproto_Log_Init(g_qprotoConfig.loggingMode);
	Qproto_Log("Meta_Attach called, installing hook...");
	Qproto_Log("qproto 0.2 Vellum authorizer built-in");
	Qproto_Log("config: RevEmu=%d(cid=%d) RevEmu2013=%d(cid=%d) SC2009=%d(cid=%d) OldRevEmu=%d(cid=%d) SXEI=%d(cid=%d) Vellum=%d(cid=%d) Steam(cid=%d) Setti(cid=%d) NoSteam47(cid=%d) NoSteam48(cid=%d) SteamPending(cid=%d) LoggingMode=%d",
		(int)g_qprotoConfig.enableRevEmu, (int)g_qprotoConfig.cidRevEmu,
		(int)g_qprotoConfig.enableRevEmu2013, (int)g_qprotoConfig.cidRevEmu2013,
		(int)g_qprotoConfig.enableSC2009, (int)g_qprotoConfig.cidSC2009,
		(int)g_qprotoConfig.enableOldRevEmu, (int)g_qprotoConfig.cidOldRevEmu,
		(int)g_qprotoConfig.enableSXEI, (int)g_qprotoConfig.cidSXEI,
		(int)g_qprotoConfig.enableVellum, (int)g_qprotoConfig.cidVellum,
		(int)g_qprotoConfig.cidSteam,
		(int)g_qprotoConfig.cidSetti,
		(int)g_qprotoConfig.cidNoSteam47, (int)g_qprotoConfig.cidNoSteam48,
		(int)g_qprotoConfig.cidSteamPending,
		g_qprotoConfig.loggingMode);

	Qproto_Bans_Load();

	if (!Qproto_Hook_Install()) {
		LOG_ERROR(PLID, "Failed to install Steam_NotifyClientConnect hook");
		Qproto_Log("Qproto_Hook_Install FAILED - see console/engine log above for dlopen/dlsym error");
		return FALSE;
	}

	return TRUE;
}

C_DLLEXPORT int Meta_Detach(PLUG_LOADTIME /*now*/, PL_UNLOAD_REASON /*reason*/)
{
	Qproto_Hook_Remove();
	Qproto_Log("Meta_Detach called, hook removed");
	Qproto_Log_Close();
	return TRUE;
}
