#include "qproto/precompiled.h"
#include <cmath>	// must precede extdll.h - see qproto_hook.cpp for why
#include <extdll.h>
#include <enginecallback.h>
#include "qproto/qproto_api.h"
#include "qproto/qproto_client_state.h"
#include "qproto/qproto_bans.h"
#include "host_crypto.h"
#include <authum/crypto.h>

#include <cstring>
#include <cstdio>

namespace {

qproto_authkind_t MapAuthKind(client_auth_kind kind)
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

qproto_keykind_t MapKeyKind(auth_key_kind kind)
{
	switch (kind) {
		case AK_HDDSN: return QPROTO_KEY_HDDSN;
		case AK_VOLUMEID: return QPROTO_KEY_VOLUMEID;
		case AK_FILEID: return QPROTO_KEY_FILEID;
		case AK_SXEID: return QPROTO_KEY_SXEID;
		default: return QPROTO_KEY_OTHER;
	}
}

} // namespace

int qproto_api_get_version_major(void) { return QPROTO_API_VERSION_MAJOR; }
int qproto_api_get_version_minor(void) { return QPROTO_API_VERSION_MINOR; }

qproto_authkind_t qproto_get_client_authkind(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? MapAuthKind(rec->authKind) : QPROTO_AUTH_NONE;
}

int qproto_get_client_protocol(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? rec->protocol : 0;
}

int qproto_get_client_userid(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? rec->userid : 0;
}

int qproto_get_client_idkind(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? (int)rec->idKind : (int)CI_UNKNOWN;
}

unsigned int qproto_get_client_steamid(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? rec->steamId : 0;
}

size_t qproto_get_client_authid_string(int index, char* outBuf, size_t outBufLen)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	if (!rec) {
		if (outBuf && outBufLen) outBuf[0] = '\0';
		return 0;
	}

	size_t len = strlen(rec->authIdString);
	if (outBuf && outBufLen) {
		size_t n = len < outBufLen - 1 ? len : outBufLen - 1;
		memcpy(outBuf, rec->authIdString, n);
		outBuf[n] = '\0';
	}
	return len;
}

unsigned int qproto_get_client_ip(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? rec->ipAddress : 0;
}

size_t qproto_format_ip(unsigned int ip, char* outBuf, size_t outBufLen)
{
	if (!outBuf || outBufLen == 0) return 0;

	const uint8_t* b = (const uint8_t*)&ip;
	char tmp[16];
	int n = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

	size_t len = (size_t)n < outBufLen - 1 ? (size_t)n : outBufLen - 1;
	memcpy(outBuf, tmp, len);
	outBuf[len] = '\0';
	return len;
}

float qproto_get_client_connect_time(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	return rec ? rec->connectTime : 0.0f;
}

size_t qproto_get_client_authkey(int index, void* outBuf, size_t outBufLen)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	if (!rec || rec->authKeyLen == 0) return 0;

	size_t n = rec->authKeyLen < outBufLen ? rec->authKeyLen : outBufLen;
	if (outBuf && n) memcpy(outBuf, rec->authKey, n);
	return rec->authKeyLen;
}

qproto_keykind_t qproto_get_client_authkeykind(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	if (!rec || rec->authKeyLen == 0) return QPROTO_KEY_NONE;
	return MapKeyKind(rec->authKeyKind);
}

int qproto_get_client_long_authid(int index, unsigned char out[QPROTO_LONG_AUTHID_LEN])
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	if (!rec || !out) return 0;

	uint8_t buf[sizeof(uint32_t) * 2];
	const uint8_t* data;
	size_t len;

	if (rec->authKeyLen > 0) {
		data = rec->authKey;
		len = rec->authKeyLen;
	}
	else {
		// No raw key on file (native Steam, or a fixed-identity kind like Setti/
		// NoSteam47/48) - hash authkind+steamid instead, so every connected client
		// still gets *some* stable id. Mirrors classic legacy long-authid hashing.
		*(uint32_t*)buf = (uint32_t)rec->authKind;
		*(uint32_t*)(buf + sizeof(uint32_t)) = rec->steamId;
		data = buf;
		len = sizeof(buf);
	}

	const authum_crypto_t *crypto = qproto_host_crypto();
	if (!crypto)
		return 0;

	unsigned char digest[AUTHUM_CRYPTO_SHA256_DIGEST_SIZE];
	if (authum_crypto_sha_hash(crypto, authum_crypto_sha_kind_256, data, len, digest,
				   sizeof digest) != AUTHUM_CRYPTO_SHA256_DIGEST_SIZE)
		return 0;
	memcpy(out, digest, QPROTO_LONG_AUTHID_LEN);
	return 1;
}

int qproto_ban_authkey(const void* key, size_t len)
{
	return qproto_bans_add((const uint8_t*)key, len) ? 1 : 0;
}

int qproto_unban_authkey(const void* key, size_t len)
{
	return qproto_bans_remove((const uint8_t*)key, len) ? 1 : 0;
}

int qproto_is_authkey_banned(const void* key, size_t len)
{
	return qproto_bans_is_banned((const uint8_t*)key, len) ? 1 : 0;
}

namespace {

// Issues "kick #<userid>" (optionally with a reason) via pfnServerCommand. `reason` is
// sanitized (quotes/newlines stripped) before going anywhere near a console command
// string - it may come from another plugin's caller-supplied text, so it's treated as
// untrusted input, not as something safe to interpolate verbatim.
void IssueKick(int userid, const char* reason)
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
	}
	else {
		snprintf(cmd, sizeof(cmd), "kick #%d\n", userid);
	}
	(*g_engfuncs.pfnServerCommand)(cmd);
}

} // namespace

int qproto_ban_client(int index)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	if (!rec || rec->authKeyLen == 0) return 0;

	if (!qproto_bans_add(rec->authKey, rec->authKeyLen)) return 0; // already banned, or table full

	IssueKick(rec->userid, "banned");
	return 1;
}

int qproto_kick_client(int index, const char* reason)
{
	const qproto_client_record* rec = qproto_client_state_get(index);
	if (!rec) return 0;

	IssueKick(rec->userid, reason);
	return 1;
}
