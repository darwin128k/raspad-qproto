// Provides the g_engfuncs global (normally defined in src/qproto/h_export.cpp) so
// bans_selftest.cpp can link qproto_bans.cpp without pulling in the rest of the
// plugin's Metamod glue - Qproto_Bans_ParseHexLine (the function actually under test)
// never calls through g_engfuncs, but the linker still needs the symbol to resolve
// since Qproto_Bans_Load()/Add()/Remove() (same translation unit) reference it.
#include <extdll.h>

enginefuncs_t g_engfuncs;
