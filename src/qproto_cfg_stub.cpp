// Provides g_qprotoConfig (default-constructed, all emulators on) for the
// self-tests, without pulling in Qproto_Cfg_Load()'s dependency on g_engfuncs
// (defined in h_export.cpp, which the tests don't link) - the tests call the
// authorizer functions directly and never invoke Qproto_Cfg_Load() itself.
#include "qproto_cfg.h"

QprotoConfig g_qprotoConfig;
