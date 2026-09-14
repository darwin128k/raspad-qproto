// Standard Metamod-P plugin boilerplate (from stub_plugin/h_export.cpp, v1.21p37).
// This is the very first thing the engine calls into a game DLL / metamod plugin:
// it hands over the engine's function table so our code can call back into the
// engine (g_engfuncs) later, e.g. from the connectionless-packet hook.

#include <extdll.h>
#include <h_export.h>

enginefuncs_t g_engfuncs;
globalvars_t* gpGlobals;

void WINAPI GiveFnptrsToDll(enginefuncs_t* pengfuncsFromEngine, globalvars_t* pGlobals)
{
	memcpy(&g_engfuncs, pengfuncsFromEngine, sizeof(enginefuncs_t));
	gpGlobals = pGlobals;
}
