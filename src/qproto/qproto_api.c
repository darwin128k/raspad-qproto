#include "qproto/qproto_api.h"
#include "qproto/qproto_client_state.h"
#include "qproto/qproto_bans.h"
#include "qproto/qproto_shared.h"
#include "host_crypto.h"
#include "host_engine.h"
#include <authum/crypto.h>

#include <string.h>
#include <stdio.h>

static qproto_auth_kind_t
map_auth_kind(client_auth_kind_t kind)
{
	switch (kind) {
	case client_auth_kind_steam: return qproto_auth_kind_steam;
	case client_auth_kind_steam_pending: return qproto_auth_kind_steam_pending;
	case client_auth_kind_setti: return qproto_auth_kind_setti;
	case client_auth_kind_no_steam_47: return qproto_auth_kind_no_steam_47;
	case client_auth_kind_no_steam_48: return qproto_auth_kind_no_steam_48;
	case client_auth_kind_old_revemu: return qproto_auth_kind_old_revemu;
	case client_auth_kind_revemu: return qproto_auth_kind_revemu;
	case client_auth_kind_steamclient_2009: return qproto_auth_kind_sc2009;
	case client_auth_kind_revemu_2013: return qproto_auth_kind_revemu_2013;
	case client_auth_kind_sxei: return qproto_auth_kind_sxei;
	case client_auth_kind_vellum: return qproto_auth_kind_vellum;
	default: return qproto_auth_kind_none;
	}
}

static qproto_key_kind_t
map_key_kind(auth_key_kind_t kind)
{
	switch (kind) {
	case auth_key_kind_hddsn: return qproto_key_kind_hddsn;
	case auth_key_kind_volumeid: return qproto_key_kind_volumeid;
	case auth_key_kind_fileid: return qproto_key_kind_fileid;
	case auth_key_kind_sxeid: return qproto_key_kind_sxeid;
	default: return qproto_key_kind_other;
	}
}

int qproto_api_get_version_major(void) { return QPROTO_API_VERSION_MAJOR; }
int qproto_api_get_version_minor(void) { return QPROTO_API_VERSION_MINOR; }

qproto_auth_kind_t
qproto_get_client_authkind(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? map_auth_kind(rec->auth_kind) : qproto_auth_kind_none;
}

int
qproto_get_client_protocol(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? rec->protocol : 0;
}

int
qproto_get_client_userid(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? rec->userid : 0;
}

int
qproto_get_client_idkind(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? (int)rec->id_kind : (int)client_id_kind_unknown;
}

unsigned int
qproto_get_client_steamid(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? rec->steam_id : 0;
}

size_t
qproto_get_client_authid_string(int index, char *out_buf, size_t out_buf_len)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	size_t len;

	if (!rec) {
		if (out_buf && out_buf_len)
			out_buf[0] = '\0';
		return 0;
	}

	len = strlen(rec->auth_id_string);
	if (out_buf && out_buf_len) {
		size_t n = len < out_buf_len - 1 ? len : out_buf_len - 1;
		memcpy(out_buf, rec->auth_id_string, n);
		out_buf[n] = '\0';
	}
	return len;
}

unsigned int
qproto_get_client_ip(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? rec->ip_address : 0;
}

size_t
qproto_format_ip(unsigned int ip, char *out_buf, size_t out_buf_len)
{
	const uint8_t *b;
	char tmp[16];
	int n;
	size_t len;

	if (!out_buf || out_buf_len == 0)
		return 0;

	b = (const uint8_t *)&ip;
	n = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

	len = (size_t)n < out_buf_len - 1 ? (size_t)n : out_buf_len - 1;
	memcpy(out_buf, tmp, len);
	out_buf[len] = '\0';
	return len;
}

float
qproto_get_client_connect_time(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	return rec ? rec->connect_time : 0.0f;
}

size_t
qproto_get_client_authkey(int index, void *out_buf, size_t out_buf_len)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	size_t n;

	if (!rec || rec->auth_key_len == 0)
		return 0;

	n = rec->auth_key_len < out_buf_len ? rec->auth_key_len : out_buf_len;
	if (out_buf && n)
		memcpy(out_buf, rec->auth_key, n);
	return rec->auth_key_len;
}

qproto_key_kind_t
qproto_get_client_authkeykind(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	if (!rec || rec->auth_key_len == 0)
		return qproto_key_kind_none;
	return map_key_kind(rec->auth_key_kind);
}

int
qproto_get_client_long_authid(int index, unsigned char out[QPROTO_LONG_AUTHID_LEN])
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	uint8_t buf[sizeof(uint32_t) * 2];
	const uint8_t *data;
	size_t len;
	const authum_crypto_t *crypto;
	unsigned char digest[AUTHUM_CRYPTO_SHA256_DIGEST_SIZE];

	if (!rec || !out)
		return 0;

	if (rec->auth_key_len > 0) {
		data = rec->auth_key;
		len = rec->auth_key_len;
	} else {
		*(uint32_t *)buf = (uint32_t)rec->auth_kind;
		*(uint32_t *)(buf + sizeof(uint32_t)) = rec->steam_id;
		data = buf;
		len = sizeof(buf);
	}

	crypto = qproto_host_crypto();
	if (!crypto)
		return 0;

	if (authum_crypto_sha_hash(crypto, authum_crypto_sha_kind_256, (authum_ptr)(void *)data,
				   (authum_usize_t)len, (authum_ptr)digest,
				   (authum_usize_t)sizeof digest) != AUTHUM_CRYPTO_SHA256_DIGEST_SIZE)
		return 0;
	memcpy(out, digest, QPROTO_LONG_AUTHID_LEN);
	return 1;
}

int
qproto_ban_authkey(const void *key, size_t len)
{
	return qproto_bans_add((const uint8_t *)key, len) ? 1 : 0;
}

int
qproto_unban_authkey(const void *key, size_t len)
{
	return qproto_bans_remove((const uint8_t *)key, len) ? 1 : 0;
}

int
qproto_is_authkey_banned(const void *key, size_t len)
{
	return qproto_bans_is_banned((const uint8_t *)key, len) ? 1 : 0;
}

static void
issue_kick(int userid, const char *reason)
{
	char cmd[192];
	if (reason && reason[0]) {
		char clean[128];
		size_t n = 0;
		for (; reason[n] && n < sizeof(clean) - 1; n++) {
			char c = reason[n];
			clean[n] = (c == '"' || c == '\n' || c == '\r' || c == ';') ? ' ' : c;
		}
		clean[n] = '\0';
		snprintf(cmd, sizeof(cmd), "kick #%d \"%s\"\n", userid, clean);
	} else {
		snprintf(cmd, sizeof(cmd), "kick #%d\n", userid);
	}
	authum_engine_server_command(qproto_host_engine(), cmd);
}

int
qproto_ban_client(int index)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	if (!rec || rec->auth_key_len == 0)
		return 0;

	if (!qproto_bans_add(rec->auth_key, rec->auth_key_len))
		return 0;

	issue_kick(rec->userid, "banned");
	return 1;
}

int
qproto_kick_client(int index, const char *reason)
{
	const qproto_client_record_t *rec = qproto_client_state_get(index);
	if (!rec)
		return 0;

	issue_kick(rec->userid, reason);
	return 1;
}
