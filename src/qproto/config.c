#include <qproto/config.h>
#include <qproto/host.h>
#include <qproto/logger.h>

#include <authum/cfg.h>
#include <authum/cstr.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>

qproto_config_t g_qproto_config = {
    .engine_layout = qproto_engine_layout_auto,

    .enable_revemu = authum_bool_true,
    .enable_revemu_2013 = authum_bool_true,
    .enable_sc2009 = authum_bool_true,
    .enable_old_revemu = authum_bool_true,
    .enable_sxei = authum_bool_true,
    .enable_vellum = authum_bool_false,

    .cid_revemu = qproto_client_id_kind_real_steam,
    .cid_revemu_2013 = qproto_client_id_kind_real_steam,
    .cid_sc2009 = qproto_client_id_kind_real_steam,
    .cid_old_revemu = qproto_client_id_kind_real_steam,
    .cid_sxei = qproto_client_id_kind_real_steam,
    .cid_vellum = qproto_client_id_kind_real_steam,
    .cid_setti = qproto_client_id_kind_steam_by_ip,
    .cid_nosteam47 = qproto_client_id_kind_deprecated,
    .cid_nosteam48 = qproto_client_id_kind_deprecated,
    .cid_steam_pending = qproto_client_id_kind_steam_id_pending,
    .cid_steam = qproto_client_id_kind_real_steam,

    .vellum_server_ip_count = 0u,
    .vellum_max_clock_skew = 86400u,

    .logging_sinks = authum_logger_sink_host,
    .logging_split = authum_logger_file_split_full,
};

/* Plain key → field map. Custom keys (engine_layout, cid_steam) stay below. */
static const authum_cfg_item_t qproto_config_items[] = {
    {"enable_revemu", authum_cfg_kind_bool, &g_qproto_config.enable_revemu, 0},
    {"enable_revemu_2013", authum_cfg_kind_bool, &g_qproto_config.enable_revemu_2013, 0},
    {"enable_sc2009", authum_cfg_kind_bool, &g_qproto_config.enable_sc2009, 0},
    {"enable_old_revemu", authum_cfg_kind_bool, &g_qproto_config.enable_old_revemu, 0},
    {"enable_sxei", authum_cfg_kind_bool, &g_qproto_config.enable_sxei, 0},
    {"enable_vellum", authum_cfg_kind_bool, &g_qproto_config.enable_vellum, 0},

    {"logging_mode", authum_cfg_kind_u32, &g_qproto_config.logging_sinks, 0},
    {"vellum_max_clock_skew", authum_cfg_kind_u32, &g_qproto_config.vellum_max_clock_skew, 0},

    {"cid_revemu", authum_cfg_kind_i32, &g_qproto_config.cid_revemu, 0},
    {"cid_revemu_2013", authum_cfg_kind_i32, &g_qproto_config.cid_revemu_2013, 0},
    {"cid_sc2009", authum_cfg_kind_i32, &g_qproto_config.cid_sc2009, 0},
    {"cid_old_revemu", authum_cfg_kind_i32, &g_qproto_config.cid_old_revemu, 0},
    {"cid_sxei", authum_cfg_kind_i32, &g_qproto_config.cid_sxei, 0},
    {"cid_vellum", authum_cfg_kind_i32, &g_qproto_config.cid_vellum, 0},
    {"cid_setti", authum_cfg_kind_i32, &g_qproto_config.cid_setti, 0},
    {"cid_nosteam47", authum_cfg_kind_i32, &g_qproto_config.cid_nosteam47, 0},
    {"cid_nosteam48", authum_cfg_kind_i32, &g_qproto_config.cid_nosteam48, 0},
    {"cid_steam_pending", authum_cfg_kind_i32, &g_qproto_config.cid_steam_pending, 0},
};

qproto_engine_layout_t
qproto_config_parse_engine_layout(const authum_char_t *value)
{
    if (authum_cstr_eq(value, "classic", authum_bool_true) ||
        authum_cstr_eq(value, "8684", authum_bool_true) ||
        authum_cstr_eq(value, "2018", authum_bool_true))
    {
        return qproto_engine_layout_classic;
    }
    if (authum_cstr_eq(value, "10211", authum_bool_true) ||
        authum_cstr_eq(value, "build10211", authum_bool_true))
    {
        return qproto_engine_layout_build10211;
    }
    return qproto_engine_layout_auto;
}

void
qproto_config_load(void)
{
    authum_path_t path;
    authum_cfg_t cfg;
    authum_char_t layout[32];
    authum_char_t split[32];
    authum_char_t server_ips[128];
    authum_i32_t cid_steam;

    if (!authum_path_join(&path, authum_host_env_module(&g_qproto_host), "qproto.cfg") ||
        !authum_cfg_open(&cfg, &path))
    {
        authum_logger_info(&g_qproto_logger, "qproto.cfg not found - using defaults");
        return;
    }

    authum_cfg_apply_items(
        &cfg, qproto_config_items,
        (authum_usize_t)(sizeof qproto_config_items / sizeof qproto_config_items[0]));

    if (authum_cfg_apply_cstr(&cfg, "engine_layout", layout, sizeof layout))
    {
        g_qproto_config.engine_layout = qproto_config_parse_engine_layout(layout);
    }

    if (authum_cfg_apply_cstr(&cfg, "logging_split", split, sizeof split))
    {
        g_qproto_config.logging_split = authum_logger_file_split_parse(split);
    }

    if (authum_cfg_apply_cstr(&cfg, "vellum_server_ip", server_ips, sizeof server_ips))
    {
        g_qproto_config.vellum_server_ip_count = qproto_vellum_parse_ip_list(
            server_ips, g_qproto_config.vellum_server_ips, QPROTO_VELLUM_MAX_SERVER_IPS);
    }

    cid_steam = (authum_i32_t)g_qproto_config.cid_steam;
    if (authum_cfg_apply_i32(&cfg, "cid_steam", &cid_steam))
    {
        if (cid_steam == (authum_i32_t)qproto_client_id_kind_steam_by_ip ||
            cid_steam == (authum_i32_t)qproto_client_id_kind_valve_by_ip ||
            cid_steam == (authum_i32_t)qproto_client_id_kind_real_steam)
        {
            g_qproto_config.cid_steam = (qproto_client_id_kind_t)cid_steam;
        }
    }

    authum_cfg_close(&cfg);

    authum_logger_info(
        &g_qproto_logger,
        "qproto.cfg loaded from %s: RevEmu=%d(cid=%d) RevEmu2013=%d(cid=%d) SC2009=%d(cid=%d) "
        "OldRevEmu=%d(cid=%d) SXEI=%d(cid=%d) Vellum=%d(cid=%d) Steam(cid=%d) Setti(cid=%d) "
        "NoSteam47(cid=%d) NoSteam48(cid=%d) SteamPending(cid=%d) logging_mode=%u logging_split=%s",
        authum_path_as_cstr(&path), (int)g_qproto_config.enable_revemu,
        (int)g_qproto_config.cid_revemu, (int)g_qproto_config.enable_revemu_2013,
        (int)g_qproto_config.cid_revemu_2013, (int)g_qproto_config.enable_sc2009,
        (int)g_qproto_config.cid_sc2009, (int)g_qproto_config.enable_old_revemu,
        (int)g_qproto_config.cid_old_revemu, (int)g_qproto_config.enable_sxei,
        (int)g_qproto_config.cid_sxei, (int)g_qproto_config.enable_vellum,
        (int)g_qproto_config.cid_vellum, (int)g_qproto_config.cid_steam,
        (int)g_qproto_config.cid_setti, (int)g_qproto_config.cid_nosteam47,
        (int)g_qproto_config.cid_nosteam48, (int)g_qproto_config.cid_steam_pending,
        (unsigned)g_qproto_config.logging_sinks,
        g_qproto_config.logging_split == authum_logger_file_split_session ? "session" : "full");
    authum_logger_info(&g_qproto_logger, "Vellum: vellum_server_ip entries=%u max_clock_skew=%us",
                       (unsigned)g_qproto_config.vellum_server_ip_count,
                       (unsigned)g_qproto_config.vellum_max_clock_skew);
}
