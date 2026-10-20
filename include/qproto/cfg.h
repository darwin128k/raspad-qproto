#ifndef QPROTO_CFG_H
#define QPROTO_CFG_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/logger/sink.h>

#include "qproto/engine.h"
#include "qproto/shared.h"

struct qproto_config
{
	/*
	 * Which client_t / export layout to use when hooking engine_i486.so.
	 * auto (default): dynsym hit ⇒ classic (8684/2018); .symtab-only ⇒ build10211.
	 * Force with EngineLayout=classic or EngineLayout=10211 in qproto.cfg.
	 */
	qproto_engine_layout_t engine_layout;

	/* Per-emulator on/off, mirroring dproto.cfg's cid_* style. */
	authum_bool_t enable_revemu; /* RevEmu >= 9.74 (152-byte "rev"-signed ticket) */
	authum_bool_t enable_revemu_2013; /* RevEmu2013 (194-byte, AES+SHA256) */
	authum_bool_t enable_sc2009; /* SteamClient 2009 (178-byte, AES+SHA256) */
	authum_bool_t enable_old_revemu; /* legacy 10-byte XOR ticket */
	authum_bool_t enable_sxei; /* sXe Injected ("*HID" userinfo key) */
	authum_bool_t enable_vellum; /* VLLM ticket — opt-in via EnableVellum=1 */

	/*
	 * cid_* (qproto_client_id_kind_t): id format after successful auth.
	 */
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

	/* LoggingMode cfg integer → authum_logger_sink_* bits. */
	authum_logger_sink_t logging_sinks;

	/* Reject messages, one per qproto_client_auth_kind_t. */
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

void qproto_cfg_init(void);
void qproto_cfg_load(void);

#endif /* QPROTO_CFG_H */
