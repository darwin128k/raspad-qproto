#include "qproto/qproto_api.h"
#include "qproto/qproto_client_state.h"
#include "qproto/qproto_bans.h"
#include "qproto/qproto_shared.h"
#include "host_crypto.h"
#include "host_engine.h"
#include <authum/crypto.h>

#include <string.h>
#include <stdio.h>

static qproto_authkind_t
map_auth_kind(enum client_auth_kind kind)
{
	switch (kind) {
	case CA_STEAM: return QPROTO_AUTH_STEAM;
	case CA_STEAM_PENDING: return QPROTO_AUTH_STEAM_PENDING;
	case CA_SETTI: return QPROTO_AUTH_SETTI;
	case CA_NO_STEAM_47: return QPROTO_AUTH_NO_STEAM_47;
	case CA_NO_STEAM_48: return QPROTO_AUTH_NO_STEAM_48;
	case CA_OLD_REVEMU: return QPROTO_AUTH_OLD_REVEMU;
	case CA_REVEMU: return QPROTO_AUTH_REVEMU;
	case CA_STEAMCLIENT_2009: return QPROTO_AUTH_SC2009;
	case CA_REVEMU_2013: return QPROTO_AUTH_REVEMU_2013;
	case CA_SXEI: return QPROTO_AUTH_SXEI;
	case CA_VELLUM: return QPROTO_AUTH_VELLUM;
	default: return QPROTO_AUTH_NONE;
	}
}

static qproto_keykind_t
map_key_kind(enum auth_key_kind kind)
{
	switch (kind) {
	case AK_HDDSN: return QPROTO_KEY_HDDSN;
	case AK_VOLUMEID: return QPROTO_KEY_VOLUMEID;
	case AK_FILEID: return QPROTO_KEY_FILEID;
	case AK_SXEID: return QPROTO_KEY_SXEID;
	default: return QPROTO_KEY_OTHER;
	}
}

int qproto_api_get_version_major(void) { return QPROTO_API_VERSION_MAJOR; }
int qproto_api_get_version_minor(void) { return QPROTO_API_VERSION_MINOR; }

qproto_authkind_t
qproto_get_client_authkind(int index)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	return rec ? map_auth_kind(rec->auth_kind) : QPROTO_AUTH_NONE;
}

int
qproto_get_client_protocol(int index)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	return rec ? rec->protocol : 0;
}

int
qproto_get_client_userid(int index)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	return rec ? rec->userid : 0;
}

int
qproto_get_client_idkind(int index)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	return rec ? (int)rec->id_kind : (int)CI_UNKNOWN;
}

unsigned int
qproto_get_client_steamid(int index)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	return rec ? rec->steam_id : 0;
}

size_t
qproto_get_client_authid_string(int index, char *out_buf, size_t out_buf_len)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
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
	const qproto_client_record *rec = qproto_client_state_get(index);
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
	const qproto_client_record *rec = qproto_client_state_get(index);
	return rec ? rec->connect_time : 0.0f;
}

size_t
qproto_get_client_authkey(int index, void *out_buf, size_t out_buf_len)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	size_t n;

	if (!rec || rec->auth_key_len == 0)
		return 0;

	n = rec->auth_key_len < out_buf_len ? rec->auth_key_len : out_buf_len;
	if (out_buf && n)
		memcpy(out_buf, rec->auth_key, n);
	return rec->auth_key_len;
}

qproto_keykind_t
qproto_get_client_authkeykind(int index)
{
	const qproto_client_record *rec = qproto_client_state_get(index);
	if (!rec || rec->auth_key_len == 0)
		return QPROTO_KEY_NONE;
	return map_key_kind(rec->auth_key_kind);
}

int
qproto_get_client_long_authid(int index, unsigned char out[QPROTO_LONG_AUTHID_LEN])
{
	const qproto_client_record *rec = qproto_client_state_get(index);
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

	if (authum_crypto_sha_hash(crypto, authum_crypto_sha_kind_256, data, len, digest,
				   sizeof digest) != AUTHUM_CRYPTO_SHA256_DIGEST_SIZE)
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
	const qproto_client_record *rec = qproto_client_state_get(index);
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
	const qproto_client_record *rec = qproto_client_state_get(index);
	if (!rec)
		return 0;

	issue_kick(rec->userid, reason);
	return 1;
}
