#include <qproto/client/auth_kind.h>

const char *
qproto_client_auth_kind_name(qproto_client_auth_kind_t kind)
{
	switch (kind) {
	case qproto_client_auth_kind_revemu: return "RevEmu";
	case qproto_client_auth_kind_revemu_2013: return "RevEmu2013";
	case qproto_client_auth_kind_steamclient_2009: return "SC2009";
	case qproto_client_auth_kind_old_revemu: return "OldRevEmu";
	case qproto_client_auth_kind_setti: return "Setti";
	case qproto_client_auth_kind_no_steam_47: return "NoSteam47";
	case qproto_client_auth_kind_no_steam_48: return "NoSteam48";
	case qproto_client_auth_kind_steam_pending: return "Steam_PENDING";
	case qproto_client_auth_kind_sxei: return "sXe";
	case qproto_client_auth_kind_vellum: return "Vellum";
	case qproto_client_auth_kind_steam: return "Steam";
	default: return "unknown";
	}
}
