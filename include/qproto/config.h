#ifndef QPROTO_CONFIG_H
#define QPROTO_CONFIG_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>

#include <qproto/engine.h>
#include <qproto/shared.h>
#include <qproto/vellum/address.h>

/**
 * Runtime settings. Defaults live on ::g_qproto_config (static init);
 * `qproto.cfg` overlays via ::authum_cfg_apply_items.
 */
struct qproto_config
{
    qproto_engine_layout_t engine_layout;

    authum_bool_t enable_revemu;
    authum_bool_t enable_revemu_2013;
    authum_bool_t enable_sc2009;
    authum_bool_t enable_old_revemu;
    authum_bool_t enable_sxei;
    authum_bool_t enable_vellum;

    qproto_client_id_kind_t cid_revemu;
    qproto_client_id_kind_t cid_revemu_2013;
    qproto_client_id_kind_t cid_sc2009;
    qproto_client_id_kind_t cid_old_revemu;
    qproto_client_id_kind_t cid_sxei;
    qproto_client_id_kind_t cid_vellum;

    qproto_client_id_kind_t cid_setti;
    qproto_client_id_kind_t cid_nosteam47;
    qproto_client_id_kind_t cid_nosteam48;
    qproto_client_id_kind_t cid_steam_pending;
    qproto_client_id_kind_t cid_steam;

    /*
     * Vellum v2: public address(es) players dial (`vellum_server_ip`, comma
     * list). Empty = take the engine's `ip` cvar; if that is unset too, only
     * the port is checked.
     */
    authum_u32_t vellum_server_ips[QPROTO_VELLUM_MAX_SERVER_IPS];
    authum_usize_t vellum_server_ip_count;
    /** Max |server clock - ticket clock|, seconds. */
    authum_u32_t vellum_max_clock_skew;

};
typedef struct qproto_config qproto_config_t;

extern qproto_config_t g_qproto_config;

/** Overlay `qproto.cfg` onto ::g_qproto_config (defaults already set). */
void
qproto_config_load(void);

#endif /* QPROTO_CONFIG_H */
