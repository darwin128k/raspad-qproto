#include "qproto/qproto_cfg.h"
#include "qproto/qproto_log.h"
#include "qproto/qproto_paths.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>

qproto_config g_qproto_config;

void
qproto_cfg_init(void)
{
	memset(&g_qproto_config, 0, sizeof(g_qproto_config));

	g_qproto_config.engine_layout = QPROTO_LAYOUT_AUTO;

	g_qproto_config.enable_revemu = 1;
	g_qproto_config.enable_revemu_2013 = 1;
	g_qproto_config.enable_sc2009 = 1;
	g_qproto_config.enable_old_revemu = 1;
	g_qproto_config.enable_sxei = 1;
	g_qproto_config.enable_vellum = 0;

	g_qproto_config.cid_revemu = CI_REAL_STEAM;
	g_qproto_config.cid_revemu_2013 = CI_REAL_STEAM;
	g_qproto_config.cid_sc2009 = CI_REAL_STEAM;
	g_qproto_config.cid_old_revemu = CI_REAL_STEAM;
	g_qproto_config.cid_sxei = CI_REAL_STEAM;
	g_qproto_config.cid_vellum = CI_REAL_STEAM;

	g_qproto_config.cid_setti = CI_STEAM_BY_IP;
	g_qproto_config.cid_nosteam47 = CI_DEPRECATED;
	g_qproto_config.cid_nosteam48 = CI_DEPRECATED;
	g_qproto_config.cid_steam_pending = CI_STEAM_ID_PENDING;
	g_qproto_config.cid_steam = CI_REAL_STEAM;

	g_qproto_config.logging_mode = rl_logfile;

	strncpy(g_qproto_config.rej_msg_unknown, "Client authorization failed.",
		sizeof(g_qproto_config.rej_msg_unknown) - 1);
	strncpy(g_qproto_config.rej_msg_banned, "You have been banned from this server (hardware ban).",
		sizeof(g_qproto_config.rej_msg_banned) - 1);
	strncpy(g_qproto_config.rej_msg_nosteam47, "Sorry, no-steam protocol 47 clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_nosteam47) - 1);
	strncpy(g_qproto_config.rej_msg_nosteam48, "Sorry, no-steam protocol 48 clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_nosteam48) - 1);
	strncpy(g_qproto_config.rej_msg_revemu, "Sorry, RevEmu clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_revemu) - 1);
	strncpy(g_qproto_config.rej_msg_revemu_2013, "Sorry, RevEmu2013 clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_revemu_2013) - 1);
	strncpy(g_qproto_config.rej_msg_sc2009, "Sorry, SC2009 clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_sc2009) - 1);
	strncpy(g_qproto_config.rej_msg_old_revemu, "Sorry, Old RevEmu clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_old_revemu) - 1);
	strncpy(g_qproto_config.rej_msg_setti, "Sorry, Setti is not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_setti) - 1);
	strncpy(g_qproto_config.rej_msg_sxei, "Sorry, sXe Injected clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_sxei) - 1);
	strncpy(g_qproto_config.rej_msg_vellum, "Sorry, Vellum clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_vellum) - 1);
	strncpy(g_qproto_config.rej_msg_steam_pending, "Sorry, unauthorized/pending clients are not allowed on this server.",
		sizeof(g_qproto_config.rej_msg_steam_pending) - 1);
}

static char *
skip_spaces(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static void
rtrim(char *s)
{
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
		s[--n] = '\0';
	}
}

void
qproto_cfg_load(void)
{
	char path[512];
	FILE *f;
	char line[256];

	f = qproto_open_data_file("qproto.cfg", path, sizeof(path));
	if (!f) {
		qproto_log("qproto.cfg not found (tried addons/qproto, gamedir, server root) - using defaults");
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		char *hash = strchr(line, '#');
		char *p;
		char *eq;
		char *key;
		char *value;
		char *key_end;

		if (hash)
			*hash = '\0';

		p = skip_spaces(line);
		rtrim(p);
		if (!*p)
			continue;

		eq = strchr(p, '=');
		if (!eq)
			continue;

		*eq = '\0';
		key = p;
		value = skip_spaces(eq + 1);

		key_end = eq - 1;
		while (key_end >= key && (*key_end == ' ' || *key_end == '\t'))
			*key_end-- = '\0';

		if (strcasecmp(key, "EngineLayout") == 0) {
			if (strcasecmp(value, "classic") == 0 || strcasecmp(value, "8684") == 0 || strcasecmp(value, "2018") == 0)
				g_qproto_config.engine_layout = QPROTO_LAYOUT_CLASSIC;
			else if (strcasecmp(value, "10211") == 0 || strcasecmp(value, "build10211") == 0)
				g_qproto_config.engine_layout = QPROTO_LAYOUT_BUILD10211;
			else
				g_qproto_config.engine_layout = QPROTO_LAYOUT_AUTO;
		} else if (strcasecmp(key, "EnableRevEmu") == 0) {
			g_qproto_config.enable_revemu = atoi(value) != 0;
		} else if (strcasecmp(key, "EnableRevEmu2013") == 0) {
			g_qproto_config.enable_revemu_2013 = atoi(value) != 0;
		} else if (strcasecmp(key, "EnableSC2009") == 0) {
			g_qproto_config.enable_sc2009 = atoi(value) != 0;
		} else if (strcasecmp(key, "EnableOldRevEmu") == 0) {
			g_qproto_config.enable_old_revemu = atoi(value) != 0;
		} else if (strcasecmp(key, "EnableSXEI") == 0) {
			g_qproto_config.enable_sxei = atoi(value) != 0;
		} else if (strcasecmp(key, "EnableVellum") == 0) {
			g_qproto_config.enable_vellum = atoi(value) != 0;
		} else if (strcasecmp(key, "LoggingMode") == 0) {
			g_qproto_config.logging_mode = atoi(value);
		} else if (strcasecmp(key, "cid_RevEmu") == 0) {
			g_qproto_config.cid_revemu = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_RevEmu2013") == 0) {
			g_qproto_config.cid_revemu_2013 = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_SC2009") == 0) {
			g_qproto_config.cid_sc2009 = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_OldRevEmu") == 0) {
			g_qproto_config.cid_old_revemu = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_SXEI") == 0) {
			g_qproto_config.cid_sxei = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_Vellum") == 0) {
			g_qproto_config.cid_vellum = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_Steam") == 0) {
			enum client_id_kind v = (enum client_id_kind)atoi(value);
			g_qproto_config.cid_steam = (v == CI_STEAM_BY_IP || v == CI_VALVE_BY_IP) ? v : CI_REAL_STEAM;
		} else if (strcasecmp(key, "cid_Setti") == 0) {
			g_qproto_config.cid_setti = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_NoSteam47") == 0) {
			g_qproto_config.cid_nosteam47 = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_NoSteam48") == 0) {
			g_qproto_config.cid_nosteam48 = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "cid_SteamPending") == 0) {
			g_qproto_config.cid_steam_pending = (enum client_id_kind)atoi(value);
		} else if (strcasecmp(key, "RejMsgUnknown") == 0) {
			strncpy(g_qproto_config.rej_msg_unknown, value, sizeof(g_qproto_config.rej_msg_unknown) - 1);
		} else if (strcasecmp(key, "RejMsgBanned") == 0) {
			strncpy(g_qproto_config.rej_msg_banned, value, sizeof(g_qproto_config.rej_msg_banned) - 1);
		} else if (strcasecmp(key, "RejMsgNoSteam47") == 0) {
			strncpy(g_qproto_config.rej_msg_nosteam47, value, sizeof(g_qproto_config.rej_msg_nosteam47) - 1);
		} else if (strcasecmp(key, "RejMsgNoSteam48") == 0) {
			strncpy(g_qproto_config.rej_msg_nosteam48, value, sizeof(g_qproto_config.rej_msg_nosteam48) - 1);
		} else if (strcasecmp(key, "RejMsgRevEmu") == 0) {
			strncpy(g_qproto_config.rej_msg_revemu, value, sizeof(g_qproto_config.rej_msg_revemu) - 1);
		} else if (strcasecmp(key, "RejMsgRevEmu2013") == 0) {
			strncpy(g_qproto_config.rej_msg_revemu_2013, value, sizeof(g_qproto_config.rej_msg_revemu_2013) - 1);
		} else if (strcasecmp(key, "RejMsgSC2009") == 0) {
			strncpy(g_qproto_config.rej_msg_sc2009, value, sizeof(g_qproto_config.rej_msg_sc2009) - 1);
		} else if (strcasecmp(key, "RejMsgOldRevEmu") == 0) {
			strncpy(g_qproto_config.rej_msg_old_revemu, value, sizeof(g_qproto_config.rej_msg_old_revemu) - 1);
		} else if (strcasecmp(key, "RejMsgSetti") == 0) {
			strncpy(g_qproto_config.rej_msg_setti, value, sizeof(g_qproto_config.rej_msg_setti) - 1);
		} else if (strcasecmp(key, "RejMsgSXEI") == 0) {
			strncpy(g_qproto_config.rej_msg_sxei, value, sizeof(g_qproto_config.rej_msg_sxei) - 1);
		} else if (strcasecmp(key, "RejMsgVellum") == 0) {
			strncpy(g_qproto_config.rej_msg_vellum, value, sizeof(g_qproto_config.rej_msg_vellum) - 1);
		} else if (strcasecmp(key, "RejMsgSteamPending") == 0) {
			strncpy(g_qproto_config.rej_msg_steam_pending, value, sizeof(g_qproto_config.rej_msg_steam_pending) - 1);
		}
	}
	fclose(f);

	qproto_log("qproto.cfg loaded from %s: RevEmu=%d(cid=%d) RevEmu2013=%d(cid=%d) SC2009=%d(cid=%d) OldRevEmu=%d(cid=%d) SXEI=%d(cid=%d) Vellum=%d(cid=%d) Steam(cid=%d) Setti(cid=%d) NoSteam47(cid=%d) NoSteam48(cid=%d) SteamPending(cid=%d) LoggingMode=%d",
		path,
		g_qproto_config.enable_revemu, (int)g_qproto_config.cid_revemu,
		g_qproto_config.enable_revemu_2013, (int)g_qproto_config.cid_revemu_2013,
		g_qproto_config.enable_sc2009, (int)g_qproto_config.cid_sc2009,
		g_qproto_config.enable_old_revemu, (int)g_qproto_config.cid_old_revemu,
		g_qproto_config.enable_sxei, (int)g_qproto_config.cid_sxei,
		g_qproto_config.enable_vellum, (int)g_qproto_config.cid_vellum,
		(int)g_qproto_config.cid_steam,
		(int)g_qproto_config.cid_setti,
		(int)g_qproto_config.cid_nosteam47, (int)g_qproto_config.cid_nosteam48,
		(int)g_qproto_config.cid_steam_pending,
		g_qproto_config.logging_mode);
}
