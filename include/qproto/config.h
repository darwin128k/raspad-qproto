#ifndef QPROTO_CONFIG_H
#define QPROTO_CONFIG_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/logger/sink.h>

#include <qproto/engine.h>
#include <qproto/shared.h>

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

	authum_logger_sink_t logging_sinks;

	authum_char_t rej_msg_unknown[128];
	authum_char_t rej_msg_banned[128];
	authum_char_t rej_msg_nosteam47[128];
	authum_char_t rej_msg_nosteam48[128];
	authum_char_t rej_msg_revemu[128];
	authum_char_t rej_msg_revemu_2013[128];
	authum_char_t rej_msg_sc2009[128];
	authum_char_t rej_msg_old_revemu[128];
	authum_char_t rej_msg_setti[128];
	authum_char_t rej_msg_sxei[128];
	authum_char_t rej_msg_vellum[128];
	authum_char_t rej_msg_steam_pending[128];
};
typedef struct qproto_config qproto_config_t;

extern qproto_config_t g_qproto_config;

/** Overlay `qproto.cfg` onto ::g_qproto_config (defaults already set). */
void qproto_config_load(void);

#endif /* QPROTO_CONFIG_H */
