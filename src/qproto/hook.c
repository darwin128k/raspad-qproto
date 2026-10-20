/*
 * The one hook qproto needs. Confirmed via Ghidra + the binary's own
 * DWARF debug info (engine_i486.so, Aug 2018 build):
 *
 *   SV_ConnectClient(): for protocol==3 (Steam) connects:
 *     qVar12 = Steam_NotifyClientConnect(client, authBuf, len);
 *     if (!qVar12) { if (!sv_lan) { SV_RejectConnection(...); return; } ... }
 *
 *   struct client_t {
 *     ...
 *     +0x4a8c  int      userid;
 *     +0x4a90  USERID_t network_userid;   // { int idtype; uint64 m_SteamID; uint clientip; }
 *     +0x4aa0  char     userinfo[256];
 *     ...
 *   };
 *
 * So: call the real Steam_NotifyClientConnect first (real Steam clients must keep
 * working exactly as before). Only when it fails do we try qproto_authorizers.c
 * on the same raw ticket bytes; on success we write directly into the client's
 * network_userid and tell SV_ConnectClient the connection is fine after all.
 */

#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <qproto/hook.h>
#include <qproto/authorizers.h>
#include <qproto/client/auth/kind.h>
#include <qproto/logger.h>
#include <qproto/config.h>
#include <qproto/client/state.h>
#include <qproto/engine.h>

typedef int (*steam_notify_client_connect_fn)(void *client, char *auth_buf, int len);
typedef char *(*cmd_argv_fn)(int);
typedef char *(*info_value_for_key_fn)(char *, char *);
typedef void (*sv_reject_connection_fn)(void *adr, const char *fmt, ...);

static void *g_hook_target;
static steam_notify_client_connect_fn g_real;
static cmd_argv_fn g_cmd_argv;
static info_value_for_key_fn g_info_value_for_key;
static sv_reject_connection_fn g_sv_reject_connection;
static unsigned char g_saved_bytes[5];
static int g_installed;
static uintptr_t g_network_userid_offset = 0x4a90;
static uintptr_t g_remote_address_offset = 0x20;

void
qproto_hook_send_reject(void *client, const char *message)
{
	void *adr;
	if (!g_sv_reject_connection)
		return;
	adr = (uint8_t *)client + g_remote_address_offset;
	g_sv_reject_connection(adr, "%s\n", message);
}

void
qproto_hook_patch_jmp(void *target, void *dest, unsigned char *save_back)
{
	uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
	size_t len = ((uintptr_t)target + 5) - page;
	unsigned char *t;
	int32_t rel;

	mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);

	if (save_back)
		memcpy(save_back, target, 5);

	t = (unsigned char *)target;
	rel = (int32_t)((uintptr_t)dest - (uintptr_t)target - 5);
	t[0] = 0xE9;
	memcpy(t + 1, &rel, 4);
}

void
qproto_hook_restore_bytes(void *target, const unsigned char *saved)
{
	uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
	size_t len = ((uintptr_t)target + 5) - page;
	mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy(target, saved, 5);
}

/* AUTH_IDTYPE from engine's userid.h: STEAM=1, VALVE=2, LOCAL=3. */
enum { AUTH_IDTYPE_STEAM = 1, AUTH_IDTYPE_VALVE = 2, AUTH_IDTYPE_LOCAL = 3 };

int
qproto_hook_auth_id_type(qproto_client_id_kind_t cid)
{
	switch (cid) {
	case qproto_client_id_kind_real_steam:
	case qproto_client_id_kind_steam_by_ip:
	case qproto_client_id_kind_steam_id_lan:
	case qproto_client_id_kind_steam_id_pending:
	case qproto_client_id_kind_steam_666_88_666:
		return AUTH_IDTYPE_STEAM;

	case qproto_client_id_kind_real_valve:
	case qproto_client_id_kind_valve_by_ip:
	case qproto_client_id_kind_valve_id_lan:
	case qproto_client_id_kind_valve_id_pending:
		return AUTH_IDTYPE_VALVE;

	case qproto_client_id_kind_hltv:
		return AUTH_IDTYPE_LOCAL;

	case qproto_client_id_kind_deprecated:
		return -1;

	default:
		return -1;
	}
}

qproto_client_id_kind_t
qproto_hook_cid_for_auth_kind(qproto_client_auth_kind_t kind)
{
	switch (kind) {
	case qproto_client_auth_kind_revemu: return g_qproto_config.cid_revemu;
	case qproto_client_auth_kind_revemu_2013: return g_qproto_config.cid_revemu_2013;
	case qproto_client_auth_kind_steamclient_2009: return g_qproto_config.cid_sc2009;
	case qproto_client_auth_kind_old_revemu: return g_qproto_config.cid_old_revemu;
	case qproto_client_auth_kind_setti: return g_qproto_config.cid_setti;
	case qproto_client_auth_kind_no_steam_47: return g_qproto_config.cid_nosteam47;
	case qproto_client_auth_kind_no_steam_48: return g_qproto_config.cid_nosteam48;
	case qproto_client_auth_kind_steam_pending: return g_qproto_config.cid_steam_pending;
	case qproto_client_auth_kind_sxei: return g_qproto_config.cid_sxei;
	case qproto_client_auth_kind_vellum: return g_qproto_config.cid_vellum;
	case qproto_client_auth_kind_steam: return g_qproto_config.cid_steam;
	default: return qproto_client_id_kind_unknown;
	}
}

int
qproto_hook_is_numeric_auth_kind(qproto_client_auth_kind_t kind)
{
	switch (kind) {
	case qproto_client_auth_kind_old_revemu: case qproto_client_auth_kind_revemu: case qproto_client_auth_kind_steamclient_2009: case qproto_client_auth_kind_revemu_2013:
	case qproto_client_auth_kind_sxei: case qproto_client_auth_kind_vellum: case qproto_client_auth_kind_steam:
		return 1;
	default:
		return 0;
	}
}

const char *
qproto_hook_reject_message(qproto_client_auth_kind_t kind)
{
	switch (kind) {
	case qproto_client_auth_kind_no_steam_47: return g_qproto_config.rej_msg_nosteam47;
	case qproto_client_auth_kind_no_steam_48: return g_qproto_config.rej_msg_nosteam48;
	case qproto_client_auth_kind_revemu: return g_qproto_config.rej_msg_revemu;
	case qproto_client_auth_kind_revemu_2013: return g_qproto_config.rej_msg_revemu_2013;
	case qproto_client_auth_kind_steamclient_2009: return g_qproto_config.rej_msg_sc2009;
	case qproto_client_auth_kind_old_revemu: return g_qproto_config.rej_msg_old_revemu;
	case qproto_client_auth_kind_setti: return g_qproto_config.rej_msg_setti;
	case qproto_client_auth_kind_sxei: return g_qproto_config.rej_msg_sxei;
	case qproto_client_auth_kind_vellum: return g_qproto_config.rej_msg_vellum;
	case qproto_client_auth_kind_steam_pending: return g_qproto_config.rej_msg_steam_pending;
	default: return g_qproto_config.rej_msg_unknown;
	}
}

int
qproto_steam_notify_client_connect_hook(void *client, char *auth_buf, int len)
{
	int protocol = 0;
	const char *sxei_hid_hex = NULL;
	int result;
	uint8_t *base;
	uint32_t client_ip;
	qproto_authdata_t authdata;
	qproto_client_auth_kind_t kind;
	qproto_client_id_kind_t cid;
	int auth_id_type;
	uint32_t final_steam_id;
	qproto_client_info_t rec;

	authum_logger_info(&g_qproto_logger, "hook fired: client=%p authBuf=%p len=%d", client, (void *)auth_buf, len);

	if (g_cmd_argv) {
		char *protinfo = g_cmd_argv(3);
		char *userinfo = g_cmd_argv(4);
		authum_logger_info(&g_qproto_logger, "Cmd_Argv(3) protinfo = '%s'", protinfo ? protinfo : "(null)");
		authum_logger_info(&g_qproto_logger, "Cmd_Argv(4) userinfo = '%s'", userinfo ? userinfo : "(null)");
		if (g_info_value_for_key && protinfo) {
			char key_cdkey[] = "cdkey";
			char key_raw[] = "raw";
			char key_prot[] = "prot";
			char *cdkey = g_info_value_for_key(protinfo, key_cdkey);
			char *raw = g_info_value_for_key(protinfo, key_raw);
			char *prot = g_info_value_for_key(protinfo, key_prot);
			authum_logger_info(&g_qproto_logger, "protinfo cdkey='%s' (len=%d)", cdkey ? cdkey : "", cdkey ? (int)strlen(cdkey) : -1);
			authum_logger_info(&g_qproto_logger, "protinfo raw='%s' (len=%d)", raw ? raw : "", raw ? (int)strlen(raw) : -1);
			protocol = prot ? atoi(prot) : 0;
		}
		if (g_info_value_for_key && userinfo) {
			char key_hid[] = "*HID";
			sxei_hid_hex = g_info_value_for_key(userinfo, key_hid);
		}
	}

	qproto_hook_restore_bytes(g_hook_target, g_saved_bytes);
	result = g_real(client, auth_buf, len);
	qproto_hook_patch_jmp(g_hook_target, (void *)&qproto_steam_notify_client_connect_hook, NULL);

	authum_logger_info(&g_qproto_logger, "native Steam_NotifyClientConnect returned %d", result);

	base = (uint8_t *)client + g_network_userid_offset;
	client_ip = *(uint32_t *)(base + 0xc);

	if (result) {
		uint32_t native_steam_id = (uint32_t)(*(uint64_t *)(base + 0x4) & 0xFFFFFFFFu);
		kind = (native_steam_id <= QPROTO_STEAM_ID_PENDING) ? qproto_client_auth_kind_steam_pending : qproto_client_auth_kind_steam;
		cid = qproto_hook_cid_for_auth_kind(kind);
		final_steam_id = native_steam_id;

		if (cid == qproto_client_id_kind_steam_by_ip || cid == qproto_client_id_kind_valve_by_ip) {
			auth_id_type = qproto_hook_auth_id_type(cid);
			final_steam_id = client_ip ^ QPROTO_IPGEN_KEY;
			*(int32_t *)(base + 0x0) = auth_id_type;
			*(uint64_t *)(base + 0x4) = (uint64_t)final_steam_id;
			authum_logger_info(&g_qproto_logger, "native Steam auth ok (%s), cid=%d overrides id -> idtype=%d steamid=%u",
				qproto_client_auth_kind_name(kind), (int)cid, auth_id_type, final_steam_id);
		} else {
			authum_logger_info(&g_qproto_logger, "native Steam auth ok (%s), cid=%d - no override configured",
				qproto_client_auth_kind_name(kind), (int)cid);
		}

		memset(&rec, 0, sizeof(rec));
		rec.protocol = protocol;
		rec.ip_address = client_ip;
		rec.auth_kind = kind;
		rec.id_kind = cid;
		rec.steam_id = final_steam_id;
		qproto_client_state_set_pending(&rec);

		return result;
	}

	memset(&authdata, 0, sizeof(authdata));
	authdata.auth_ticket = (const authum_byte_t *)auth_buf;
	authdata.ticket_len = (authum_usize_t)(auth_buf ? len : 0);
	authdata.protocol = protocol;
	authdata.sxei_hid_hex = sxei_hid_hex;

	if (auth_buf && len > 0) {
		authum_logger_hex_dump(&g_qproto_logger, "ticket bytes", (authum_ptr)(void *)auth_buf,
				       (authum_usize_t)len);
	}

	kind = qproto_authorize_client(&authdata, authum_bool_true, authum_bool_true);

	if (kind == qproto_client_auth_kind_unknown) {
		authum_logger_info(&g_qproto_logger, "no authorizer matched (protocol=%d, ticketLen=%d) - keeping native rejection",
			authdata.protocol, (int)authdata.ticket_len);
		qproto_hook_send_reject(client, g_qproto_config.rej_msg_unknown);
		return 0;
	}

	if (authdata.auth_key_len > 0) {
		char hex[QPROTO_MAX_AUTHKEY_LEN * 2 + 1];
		size_t i;
		for (i = 0; i < authdata.auth_key_len; i++) {
			snprintf(hex + i * 2, 3, "%02x", (unsigned)(authum_byte_t)authdata.auth_key[i]);
		}
		authum_logger_info(&g_qproto_logger, "raw auth key (%s, hex): %s",
			qproto_client_auth_kind_name(kind), hex);
	}

	if (qproto_hook_is_numeric_auth_kind(kind) && authdata.steam_id <= QPROTO_STEAM_ID_PENDING) {
		kind = qproto_client_auth_kind_steam_pending;
	}

	cid = qproto_hook_cid_for_auth_kind(kind);
	auth_id_type = qproto_hook_auth_id_type(cid);
	if (auth_id_type < 0) {
		authum_logger_info(&g_qproto_logger, "%s authorized but cid=%d (dproto.cfg-style) means reject - keeping native rejection",
			qproto_client_auth_kind_name(kind), (int)cid);
		qproto_hook_send_reject(client, qproto_hook_reject_message(kind));
		return 0;
	}

	final_steam_id = authdata.steam_id;
	if (cid == qproto_client_id_kind_steam_by_ip || cid == qproto_client_id_kind_valve_by_ip) {
		final_steam_id = client_ip ^ QPROTO_IPGEN_KEY;
	}

	*(int32_t *)(base + 0x0) = auth_id_type;
	*(uint64_t *)(base + 0x4) = (uint64_t)final_steam_id;

	authum_logger_info(&g_qproto_logger, "emulated auth ok (%s), cid=%d -> idtype=%d, steamid=%u",
		qproto_client_auth_kind_name(kind), (int)cid, auth_id_type, final_steam_id);

	memset(&rec, 0, sizeof(rec));
	rec.protocol = protocol;
	rec.ip_address = client_ip;
	rec.auth_kind = kind;
	rec.id_kind = cid;
	rec.steam_id = final_steam_id;
	rec.auth_key_kind = authdata.auth_key_kind;
	rec.auth_key_len = authdata.auth_key_len;
	if (authdata.auth_key_len > 0 && authdata.auth_key_len <= sizeof rec.auth_key) {
		memcpy(rec.auth_key, authdata.auth_key, authdata.auth_key_len);
	} else {
		rec.auth_key_len = 0;
	}
	qproto_client_state_set_pending(&rec);

	return 1;
}

int
qproto_hook_install(void)
{
	int via_dynsym = 0;
	void *sym;
	const qproto_engine_layout_info_t *layout;

	if (g_installed)
		return 1;

	sym = qproto_engine_resolve("Steam_NotifyClientConnect", &via_dynsym);
	if (!sym) {
		authum_logger_info(&g_qproto_logger, "resolve(Steam_NotifyClientConnect) FAILED");
		return 0;
	}

	layout = qproto_engine_select_layout(g_qproto_config.engine_layout, via_dynsym);
	g_network_userid_offset = layout->network_userid_offset;
	g_remote_address_offset = layout->remote_address_offset;
	authum_logger_info(&g_qproto_logger, "engine layout: %s (override=%s, viaDynsym=%d) network_userid=+0x%lx remote_address=+0x%lx",
		layout->name,
		qproto_engine_layout_name(g_qproto_config.engine_layout),
		via_dynsym,
		(unsigned long)g_network_userid_offset,
		(unsigned long)g_remote_address_offset);

	g_hook_target = sym;
	g_real = (steam_notify_client_connect_fn)sym;

	g_cmd_argv = (cmd_argv_fn)qproto_engine_resolve("Cmd_Argv", NULL);
	g_info_value_for_key = (info_value_for_key_fn)qproto_engine_resolve("Info_ValueForKey", NULL);
	g_sv_reject_connection = (sv_reject_connection_fn)qproto_engine_resolve("SV_RejectConnection", NULL);
	authum_logger_info(&g_qproto_logger, "Cmd_Argv=%p Info_ValueForKey=%p SV_RejectConnection=%p",
		(void *)g_cmd_argv, (void *)g_info_value_for_key, (void *)g_sv_reject_connection);

	qproto_hook_patch_jmp(g_hook_target, (void *)&qproto_steam_notify_client_connect_hook, g_saved_bytes);
	g_installed = 1;
	authum_logger_info(&g_qproto_logger, "hook installed on Steam_NotifyClientConnect @ %p", g_hook_target);
	return 1;
}

void
qproto_hook_remove(void)
{
	if (!g_installed)
		return;
	qproto_hook_restore_bytes(g_hook_target, g_saved_bytes);
	g_installed = 0;
	authum_logger_info(&g_qproto_logger, "hook removed, original bytes restored");
}
