#include <cmath>	// must precede extdll.h - see qproto_hook.cpp for why
#include <extdll.h>
#include <enginecallback.h>
#include "qproto/qproto_cfg.h"
#include "qproto/qproto_log.h"
#include "qproto/qproto_paths.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <strings.h>	// strcasecmp

qproto_config g_qproto_config;

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

void qproto_cfg_load()
{
	// First hit wins: addons/qproto/ → gamedir (cstrike/) → HLDS root. See qproto_paths.h.
	char path[512];
	FILE* f = qproto_open_data_file("qproto.cfg", path, sizeof(path));
	if (!f) {
		qproto_log("qproto.cfg not found (tried addons/qproto, gamedir, server root) - using defaults");
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

		if (strcasecmp(key, "EngineLayout") == 0) {
			if (strcasecmp(value, "classic") == 0 || strcasecmp(value, "8684") == 0 || strcasecmp(value, "2018") == 0)
				g_qproto_config.engineLayout = QPROTO_LAYOUT_CLASSIC;
			else if (strcasecmp(value, "10211") == 0 || strcasecmp(value, "build10211") == 0)
				g_qproto_config.engineLayout = QPROTO_LAYOUT_BUILD10211;
			else
				g_qproto_config.engineLayout = QPROTO_LAYOUT_AUTO;
		}
		else if (strcasecmp(key, "EnableRevEmu") == 0) {
			g_qproto_config.enableRevEmu = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableRevEmu2013") == 0) {
			g_qproto_config.enableRevEmu2013 = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableSC2009") == 0) {
			g_qproto_config.enableSC2009 = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableOldRevEmu") == 0) {
			g_qproto_config.enableOldRevEmu = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableSXEI") == 0) {
			g_qproto_config.enableSXEI = atoi(value) != 0;
		}
		else if (strcasecmp(key, "EnableVellum") == 0) {
			g_qproto_config.enableVellum = atoi(value) != 0;
		}
		else if (strcasecmp(key, "LoggingMode") == 0) {
			g_qproto_config.loggingMode = atoi(value);
		}
		else if (strcasecmp(key, "cid_RevEmu") == 0) {
			g_qproto_config.cidRevEmu = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_RevEmu2013") == 0) {
			g_qproto_config.cidRevEmu2013 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_SC2009") == 0) {
			g_qproto_config.cidSC2009 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_OldRevEmu") == 0) {
			g_qproto_config.cidOldRevEmu = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_SXEI") == 0) {
			g_qproto_config.cidSXEI = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_Vellum") == 0) {
			g_qproto_config.cidVellum = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_Steam") == 0) {
			// Only CI_REAL_STEAM (passthrough) and CI_STEAM_BY_IP/CI_VALVE_BY_IP (id
			// override) are actually enforced for a native-Steam-authenticated client -
			// see qproto_hook.cpp's native-success branch. Anything else (notably
			// CI_DEPRECATED - rejecting a client the engine already authenticated via
			// Steam isn't something qproto can safely do without further engine
			// investigation) is clamped to CI_REAL_STEAM here rather than accepted and
			// silently ignored per-connection.
			client_id_kind v = (client_id_kind)atoi(value);
			g_qproto_config.cidSteam = (v == CI_STEAM_BY_IP || v == CI_VALVE_BY_IP) ? v : CI_REAL_STEAM;
		}
		else if (strcasecmp(key, "cid_Setti") == 0) {
			g_qproto_config.cidSetti = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_NoSteam47") == 0) {
			g_qproto_config.cidNoSteam47 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_NoSteam48") == 0) {
			g_qproto_config.cidNoSteam48 = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "cid_SteamPending") == 0) {
			g_qproto_config.cidSteamPending = (client_id_kind)atoi(value);
		}
		else if (strcasecmp(key, "RejMsgUnknown") == 0) {
			strncpy(g_qproto_config.rejMsgUnknown, value, sizeof(g_qproto_config.rejMsgUnknown) - 1);
		}
		else if (strcasecmp(key, "RejMsgBanned") == 0) {
			strncpy(g_qproto_config.rejMsgBanned, value, sizeof(g_qproto_config.rejMsgBanned) - 1);
		}
		else if (strcasecmp(key, "RejMsgNoSteam47") == 0) {
			strncpy(g_qproto_config.rejMsgNoSteam47, value, sizeof(g_qproto_config.rejMsgNoSteam47) - 1);
		}
		else if (strcasecmp(key, "RejMsgNoSteam48") == 0) {
			strncpy(g_qproto_config.rejMsgNoSteam48, value, sizeof(g_qproto_config.rejMsgNoSteam48) - 1);
		}
		else if (strcasecmp(key, "RejMsgRevEmu") == 0) {
			strncpy(g_qproto_config.rejMsgRevEmu, value, sizeof(g_qproto_config.rejMsgRevEmu) - 1);
		}
		else if (strcasecmp(key, "RejMsgRevEmu2013") == 0) {
			strncpy(g_qproto_config.rejMsgRevEmu2013, value, sizeof(g_qproto_config.rejMsgRevEmu2013) - 1);
		}
		else if (strcasecmp(key, "RejMsgSC2009") == 0) {
			strncpy(g_qproto_config.rejMsgSC2009, value, sizeof(g_qproto_config.rejMsgSC2009) - 1);
		}
		else if (strcasecmp(key, "RejMsgOldRevEmu") == 0) {
			strncpy(g_qproto_config.rejMsgOldRevEmu, value, sizeof(g_qproto_config.rejMsgOldRevEmu) - 1);
		}
		else if (strcasecmp(key, "RejMsgSetti") == 0) {
			strncpy(g_qproto_config.rejMsgSetti, value, sizeof(g_qproto_config.rejMsgSetti) - 1);
		}
		else if (strcasecmp(key, "RejMsgSXEI") == 0) {
			strncpy(g_qproto_config.rejMsgSXEI, value, sizeof(g_qproto_config.rejMsgSXEI) - 1);
		}
		else if (strcasecmp(key, "RejMsgVellum") == 0) {
			strncpy(g_qproto_config.rejMsgVellum, value, sizeof(g_qproto_config.rejMsgVellum) - 1);
		}
		else if (strcasecmp(key, "RejMsgSteamPending") == 0) {
			strncpy(g_qproto_config.rejMsgSteamPending, value, sizeof(g_qproto_config.rejMsgSteamPending) - 1);
		}
	}
	fclose(f);

	// Note: this fires before qproto_log_init() (we have to read LoggingMode before
	// deciding whether to open the log file at all), so it silently no-ops here - see
	// the "config: ..." line logged right after qproto_log_init() in Meta_Attach instead.
	qproto_log("qproto.cfg loaded from %s: RevEmu=%d(cid=%d) RevEmu2013=%d(cid=%d) SC2009=%d(cid=%d) OldRevEmu=%d(cid=%d) SXEI=%d(cid=%d) Vellum=%d(cid=%d) Steam(cid=%d) Setti(cid=%d) NoSteam47(cid=%d) NoSteam48(cid=%d) SteamPending(cid=%d) LoggingMode=%d",
		path,
		(int)g_qproto_config.enableRevEmu, (int)g_qproto_config.cidRevEmu,
		(int)g_qproto_config.enableRevEmu2013, (int)g_qproto_config.cidRevEmu2013,
		(int)g_qproto_config.enableSC2009, (int)g_qproto_config.cidSC2009,
		(int)g_qproto_config.enableOldRevEmu, (int)g_qproto_config.cidOldRevEmu,
		(int)g_qproto_config.enableSXEI, (int)g_qproto_config.cidSXEI,
		(int)g_qproto_config.enableVellum, (int)g_qproto_config.cidVellum,
		(int)g_qproto_config.cidSteam,
		(int)g_qproto_config.cidSetti,
		(int)g_qproto_config.cidNoSteam47, (int)g_qproto_config.cidNoSteam48,
		(int)g_qproto_config.cidSteamPending,
		g_qproto_config.loggingMode);
}
