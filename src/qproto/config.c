#include <qproto/config.h>
#include <qproto/logger.h>
#include <qproto/paths.h>

#include <authum/cfg.h>
#include <authum/cstr.h>
#include <authum/null.h>
#include <authum/path.h>

#include <stdio.h>
#include <string.h>

qproto_config_t g_qproto_config;

static qproto_engine_layout_t
qproto_config_parse_engine_layout(const authum_char_t *value)
{
	if (authum_cstr_eq(value, "classic", authum_bool_true) ||
	    authum_cstr_eq(value, "8684", authum_bool_true) ||
	    authum_cstr_eq(value, "2018", authum_bool_true))
		return qproto_engine_layout_classic;
	if (authum_cstr_eq(value, "10211", authum_bool_true) ||
	    authum_cstr_eq(value, "build10211", authum_bool_true))
		return qproto_engine_layout_build10211;
	return qproto_engine_layout_auto;
}

static qproto_client_id_kind_t
qproto_config_parse_cid_steam(authum_i32_t v, qproto_client_id_kind_t default_value)
{
	if (v == (authum_i32_t)qproto_client_id_kind_steam_by_ip ||
	    v == (authum_i32_t)qproto_client_id_kind_valve_by_ip)
		return (qproto_client_id_kind_t)v;
	if (v == (authum_i32_t)qproto_client_id_kind_real_steam)
		return qproto_client_id_kind_real_steam;
	return default_value;
}

void
qproto_config_load(void)
{
	authum_path_t path;
	authum_cfg_t cfg;
	FILE *f;
	authum_char_t layout[32];
	authum_i32_t cid_steam_default = (authum_i32_t)qproto_client_id_kind_real_steam;

	memset(&g_qproto_config, 0, sizeof(g_qproto_config));

	/* Defaults — also passed into every authum_cfg_* get below. */
	g_qproto_config.engine_layout = qproto_engine_layout_auto;
	g_qproto_config.enable_revemu = authum_bool_true;
	g_qproto_config.enable_revemu_2013 = authum_bool_true;
	g_qproto_config.enable_sc2009 = authum_bool_true;
	g_qproto_config.enable_old_revemu = authum_bool_true;
	g_qproto_config.enable_sxei = authum_bool_true;
	g_qproto_config.enable_vellum = authum_bool_false;

	g_qproto_config.cid_revemu = qproto_client_id_kind_real_steam;
	g_qproto_config.cid_revemu_2013 = qproto_client_id_kind_real_steam;
	g_qproto_config.cid_sc2009 = qproto_client_id_kind_real_steam;
	g_qproto_config.cid_old_revemu = qproto_client_id_kind_real_steam;
	g_qproto_config.cid_sxei = qproto_client_id_kind_real_steam;
	g_qproto_config.cid_vellum = qproto_client_id_kind_real_steam;
	g_qproto_config.cid_setti = qproto_client_id_kind_steam_by_ip;
	g_qproto_config.cid_nosteam47 = qproto_client_id_kind_deprecated;
	g_qproto_config.cid_nosteam48 = qproto_client_id_kind_deprecated;
	g_qproto_config.cid_steam_pending = qproto_client_id_kind_steam_id_pending;
	g_qproto_config.cid_steam = qproto_client_id_kind_real_steam;
	g_qproto_config.logging_sinks = authum_logger_sink_file;

	(void)authum_cstr_copy(g_qproto_config.rej_msg_unknown, sizeof g_qproto_config.rej_msg_unknown,
			       "Client authorization failed.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_banned, sizeof g_qproto_config.rej_msg_banned,
			       "You have been banned from this server (hardware ban).");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_nosteam47, sizeof g_qproto_config.rej_msg_nosteam47,
			       "Sorry, no-steam protocol 47 clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_nosteam48, sizeof g_qproto_config.rej_msg_nosteam48,
			       "Sorry, no-steam protocol 48 clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_revemu, sizeof g_qproto_config.rej_msg_revemu,
			       "Sorry, RevEmu clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_revemu_2013,
			       sizeof g_qproto_config.rej_msg_revemu_2013,
			       "Sorry, RevEmu2013 clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_sc2009, sizeof g_qproto_config.rej_msg_sc2009,
			       "Sorry, SC2009 clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_old_revemu,
			       sizeof g_qproto_config.rej_msg_old_revemu,
			       "Sorry, Old RevEmu clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_setti, sizeof g_qproto_config.rej_msg_setti,
			       "Sorry, Setti is not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_sxei, sizeof g_qproto_config.rej_msg_sxei,
			       "Sorry, sXe Injected clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_vellum, sizeof g_qproto_config.rej_msg_vellum,
			       "Sorry, Vellum clients are not allowed on this server.");
	(void)authum_cstr_copy(g_qproto_config.rej_msg_steam_pending,
			       sizeof g_qproto_config.rej_msg_steam_pending,
			       "Sorry, unauthorized/pending clients are not allowed on this server.");

	authum_path_clear(&path);
	f = qproto_open_data_file("qproto.cfg", &path);
	if (authum_null_eq(f) || !authum_cfg_adopt(&cfg, f)) {
		if (!authum_null_eq(f))
			fclose(f);
		authum_logger_info(&g_qproto_logger,
				   "qproto.cfg not found - using defaults");
		return;
	}

	(void)authum_cfg_get_cstr(&cfg, "EngineLayout", layout, sizeof layout, "auto");
	g_qproto_config.engine_layout = qproto_config_parse_engine_layout(layout);

	g_qproto_config.enable_revemu =
		authum_cfg_get_bool(&cfg, "EnableRevEmu", g_qproto_config.enable_revemu);
	g_qproto_config.enable_revemu_2013 =
		authum_cfg_get_bool(&cfg, "EnableRevEmu2013", g_qproto_config.enable_revemu_2013);
	g_qproto_config.enable_sc2009 =
		authum_cfg_get_bool(&cfg, "EnableSC2009", g_qproto_config.enable_sc2009);
	g_qproto_config.enable_old_revemu =
		authum_cfg_get_bool(&cfg, "EnableOldRevEmu", g_qproto_config.enable_old_revemu);
	g_qproto_config.enable_sxei =
		authum_cfg_get_bool(&cfg, "EnableSXEI", g_qproto_config.enable_sxei);
	g_qproto_config.enable_vellum =
		authum_cfg_get_bool(&cfg, "EnableVellum", g_qproto_config.enable_vellum);

	g_qproto_config.logging_sinks = (authum_logger_sink_t)authum_cfg_get_u32(
		&cfg, "LoggingMode", (authum_u32_t)g_qproto_config.logging_sinks);

	g_qproto_config.cid_revemu = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_RevEmu", (authum_i32_t)g_qproto_config.cid_revemu);
	g_qproto_config.cid_revemu_2013 = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_RevEmu2013", (authum_i32_t)g_qproto_config.cid_revemu_2013);
	g_qproto_config.cid_sc2009 = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_SC2009", (authum_i32_t)g_qproto_config.cid_sc2009);
	g_qproto_config.cid_old_revemu = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_OldRevEmu", (authum_i32_t)g_qproto_config.cid_old_revemu);
	g_qproto_config.cid_sxei = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_SXEI", (authum_i32_t)g_qproto_config.cid_sxei);
	g_qproto_config.cid_vellum = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_Vellum", (authum_i32_t)g_qproto_config.cid_vellum);
	g_qproto_config.cid_setti = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_Setti", (authum_i32_t)g_qproto_config.cid_setti);
	g_qproto_config.cid_nosteam47 = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_NoSteam47", (authum_i32_t)g_qproto_config.cid_nosteam47);
	g_qproto_config.cid_nosteam48 = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_NoSteam48", (authum_i32_t)g_qproto_config.cid_nosteam48);
	g_qproto_config.cid_steam_pending = (qproto_client_id_kind_t)authum_cfg_get_i32(
		&cfg, "cid_SteamPending", (authum_i32_t)g_qproto_config.cid_steam_pending);
	g_qproto_config.cid_steam = qproto_config_parse_cid_steam(
		authum_cfg_get_i32(&cfg, "cid_Steam", cid_steam_default),
		g_qproto_config.cid_steam);

	(void)authum_cfg_get_cstr(&cfg, "RejMsgUnknown", g_qproto_config.rej_msg_unknown,
			      sizeof g_qproto_config.rej_msg_unknown,
			      g_qproto_config.rej_msg_unknown);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgBanned", g_qproto_config.rej_msg_banned,
			      sizeof g_qproto_config.rej_msg_banned, g_qproto_config.rej_msg_banned);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgNoSteam47", g_qproto_config.rej_msg_nosteam47,
			      sizeof g_qproto_config.rej_msg_nosteam47,
			      g_qproto_config.rej_msg_nosteam47);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgNoSteam48", g_qproto_config.rej_msg_nosteam48,
			      sizeof g_qproto_config.rej_msg_nosteam48,
			      g_qproto_config.rej_msg_nosteam48);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgRevEmu", g_qproto_config.rej_msg_revemu,
			      sizeof g_qproto_config.rej_msg_revemu, g_qproto_config.rej_msg_revemu);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgRevEmu2013", g_qproto_config.rej_msg_revemu_2013,
			      sizeof g_qproto_config.rej_msg_revemu_2013,
			      g_qproto_config.rej_msg_revemu_2013);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgSC2009", g_qproto_config.rej_msg_sc2009,
			      sizeof g_qproto_config.rej_msg_sc2009, g_qproto_config.rej_msg_sc2009);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgOldRevEmu", g_qproto_config.rej_msg_old_revemu,
			      sizeof g_qproto_config.rej_msg_old_revemu,
			      g_qproto_config.rej_msg_old_revemu);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgSetti", g_qproto_config.rej_msg_setti,
			      sizeof g_qproto_config.rej_msg_setti, g_qproto_config.rej_msg_setti);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgSXEI", g_qproto_config.rej_msg_sxei,
			      sizeof g_qproto_config.rej_msg_sxei, g_qproto_config.rej_msg_sxei);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgVellum", g_qproto_config.rej_msg_vellum,
			      sizeof g_qproto_config.rej_msg_vellum, g_qproto_config.rej_msg_vellum);
	(void)authum_cfg_get_cstr(&cfg, "RejMsgSteamPending", g_qproto_config.rej_msg_steam_pending,
			      sizeof g_qproto_config.rej_msg_steam_pending,
			      g_qproto_config.rej_msg_steam_pending);

	authum_cfg_close(&cfg);

	authum_logger_info(
		&g_qproto_logger,
		"qproto.cfg loaded from %s: RevEmu=%d(cid=%d) RevEmu2013=%d(cid=%d) SC2009=%d(cid=%d) "
		"OldRevEmu=%d(cid=%d) SXEI=%d(cid=%d) Vellum=%d(cid=%d) Steam(cid=%d) Setti(cid=%d) "
		"NoSteam47(cid=%d) NoSteam48(cid=%d) SteamPending(cid=%d) LoggingMode=%u",
		authum_path_as_cstr(&path), (int)g_qproto_config.enable_revemu,
		(int)g_qproto_config.cid_revemu, (int)g_qproto_config.enable_revemu_2013,
		(int)g_qproto_config.cid_revemu_2013, (int)g_qproto_config.enable_sc2009,
		(int)g_qproto_config.cid_sc2009, (int)g_qproto_config.enable_old_revemu,
		(int)g_qproto_config.cid_old_revemu, (int)g_qproto_config.enable_sxei,
		(int)g_qproto_config.cid_sxei, (int)g_qproto_config.enable_vellum,
		(int)g_qproto_config.cid_vellum, (int)g_qproto_config.cid_steam,
		(int)g_qproto_config.cid_setti, (int)g_qproto_config.cid_nosteam47,
		(int)g_qproto_config.cid_nosteam48, (int)g_qproto_config.cid_steam_pending,
		(unsigned)g_qproto_config.logging_sinks);
}
