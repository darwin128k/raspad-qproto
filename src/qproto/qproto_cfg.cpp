#include <cmath>	// must precede extdll.h - see qproto_hook.cpp for why
#include <extdll.h>
#include <enginecallback.h>
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_log.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <strings.h>	// strcasecmp

QprotoConfig g_qprotoConfig;

namespace {

char* SkipSpaces(char* s)
{
	while (*s == ' ' || *s == '\t') s++;
	return s;
}

void RTrim(char* s)
{
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
		s[--n] = '\0';
	}
}

} // namespace

void Qproto_Cfg_Load()
{
	char gameDir[256] = {};
	(*g_engfuncs.pfnGetGameDir)(gameDir);

	// dproto.cfg lives at the server root (one level above the mod dir, e.g. "cstrike/..")
	// - match that convention so admins have one place to look for both.
	char path[512];
	snprintf(path, sizeof(path), "%s/../qproto.cfg", gameDir);

	FILE* f = fopen(path, "r");
	if (!f) {
		Qproto_Log("qproto.cfg not found at %s - using defaults (AllowIPFallback=0)", path);
		return;
	}

	char line[256];
	while (fgets(line, sizeof(line), f)) {
		char* hash = strchr(line, '#');
		if (hash) *hash = '\0';

		char* p = SkipSpaces(line);
		RTrim(p);
		if (!*p) continue;

		char* eq = strchr(p, '=');
		if (!eq) continue;

		*eq = '\0';
		char* key = p;
		char* value = SkipSpaces(eq + 1);

		// trim trailing spaces off the key
		char* keyEnd = eq - 1;
		while (keyEnd >= key && (*keyEnd == ' ' || *keyEnd == '\t')) *keyEnd-- = '\0';

		if (strcasecmp(key, "EnableRevEmu") == 0) {
			g_qprotoConfig.enableRevEmu = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableRevEmu2013") == 0) {
			g_qprotoConfig.enableRevEmu2013 = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableSC2009") == 0) {
			g_qprotoConfig.enableSC2009 = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableOldRevEmu") == 0) {
			g_qprotoConfig.enableOldRevEmu = atoi(value) != 0;
		}
		else if (strcasecmp(key, "LoggingMode") == 0) {
			g_qprotoConfig.loggingMode = atoi(value);
		}
		else if (strcasecmp(key, "cid_RevEmu") == 0) {
			g_qprotoConfig.cidRevEmu = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_RevEmu2013") == 0) {
			g_qprotoConfig.cidRevEmu2013 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_SC2009") == 0) {
			g_qprotoConfig.cidSC2009 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_OldRevEmu") == 0) {
			g_qprotoConfig.cidOldRevEmu = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_HLTV") == 0) {
			g_qprotoConfig.cidHLTV = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_Setti") == 0) {
			g_qprotoConfig.cidSetti = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_NoSteam47") == 0) {
			g_qprotoConfig.cidNoSteam47 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_NoSteam48") == 0) {
			g_qprotoConfig.cidNoSteam48 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_SteamPending") == 0) {
			g_qprotoConfig.cidSteamPending = (client_id_kind)atoi(value);
		}
	}
	fclose(f);

	// Note: this fires before Qproto_Log_Init() (we have to read LoggingMode before
	// deciding whether to open the log file at all), so it silently no-ops here - see
	// the "config: ..." line logged right after Qproto_Log_Init() in Meta_Attach instead.
	Qproto_Log("qproto.cfg loaded from %s: RevEmu=%d(cid=%d) RevEmu2013=%d(cid=%d) SC2009=%d(cid=%d) OldRevEmu=%d(cid=%d) HLTV(cid=%d) Setti(cid=%d) NoSteam47(cid=%d) NoSteam48(cid=%d) SteamPending(cid=%d) LoggingMode=%d",
		path,
		(int)g_qprotoConfig.enableRevEmu, (int)g_qprotoConfig.cidRevEmu,
		(int)g_qprotoConfig.enableRevEmu2013, (int)g_qprotoConfig.cidRevEmu2013,
		(int)g_qprotoConfig.enableSC2009, (int)g_qprotoConfig.cidSC2009,
		(int)g_qprotoConfig.enableOldRevEmu, (int)g_qprotoConfig.cidOldRevEmu,
		(int)g_qprotoConfig.cidHLTV, (int)g_qprotoConfig.cidSetti,
		(int)g_qprotoConfig.cidNoSteam47, (int)g_qprotoConfig.cidNoSteam48,
		(int)g_qprotoConfig.cidSteamPending,
		g_qprotoConfig.loggingMode);
}
