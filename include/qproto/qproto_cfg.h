#ifndef QPROTO_CFG_H
#define QPROTO_CFG_H

#include "qproto/qproto_shared.h"
#include "qproto/qproto_engine.h"

typedef struct qproto_config {
	/*
	 * Which client_t / export layout to use when hooking engine_i486.so.
	 * auto (default): dynsym hit ⇒ classic (8684/2018); .symtab-only ⇒ build10211.
	 * Force with EngineLayout=classic or EngineLayout=10211 in qproto.cfg.
	 */
	enum qproto_engine_layout engine_layout;

	/* Per-emulator on/off switches, mirroring dproto.cfg's cid_* style. */
	int enable_revemu;		/* RevEmu >= 9.74 (152-byte "rev"-signed ticket) */
	int enable_revemu_2013;		/* RevEmu2013 (194-byte, AES+SHA256) */
	int enable_sc2009;		/* SteamClient 2009 (178-byte, AES+SHA256) */
	int enable_old_revemu;		/* legacy 10-byte XOR ticket */
	int enable_sxei;		/* sXe Injected anti-cheat hardware id ("*HID" userinfo key) */
	int enable_vellum;		/* VLLM ticket — opt-in via EnableVellum=1 in qproto.cfg */

	/*
	 * cid_* (client_id_kind, same numbering/meaning as dproto.cfg's cid_RevEmu etc.):
	 * which id format a successfully authorized client of that emulator/auth-kind gets.
	 */
	enum client_id_kind cid_revemu;
	enum client_id_kind cid_revemu_2013;
	enum client_id_kind cid_sc2009;
	enum client_id_kind cid_old_revemu;
	enum client_id_kind cid_sxei;
	enum client_id_kind cid_vellum;

	enum client_id_kind cid_setti;
	enum client_id_kind cid_nosteam47;
	enum client_id_kind cid_nosteam48;
	enum client_id_kind cid_steam_pending;

	enum client_id_kind cid_steam;

	/* LoggingMode bitmask: rl_none=0, rl_console=1, rl_logfile=2, rl_host=4. */
	int logging_mode;

	/* Messages shown to a REJECTED client, one per client_auth_kind. */
	char rej_msg_unknown[128];
	char rej_msg_banned[128];
	char rej_msg_nosteam47[128];
	char rej_msg_nosteam48[128];
	char rej_msg_revemu[128];
	char rej_msg_revemu_2013[128];
	char rej_msg_sc2009[128];
	char rej_msg_old_revemu[128];
	char rej_msg_setti[128];
	char rej_msg_sxei[128];
	char rej_msg_vellum[128];
	char rej_msg_steam_pending[128];
} qproto_config;

extern qproto_config g_qproto_config;

void qproto_cfg_init(void);
void qproto_cfg_load(void);

#endif /* QPROTO_CFG_H */
