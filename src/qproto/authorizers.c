#include <qproto/authorizers.h>
#include <qproto/utils.h>
#include <qproto/mini/steamid.h>
#include <qproto/config.h>
#include <qproto/vellum/ticket.h>
#include <qproto/host.h>
#include <authum/crypto.h>
#include <authum/null.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Taken from classic HLDS auth: authorizer.cpp (GPLv3): the RevEmu-family ticket
 * format and crypto is identical across dproto/qproto. Rijndael + SHA go through
 * Authum crypto facade (lh inside authum_mm).
 */

#define IDREVHEADER	(('r' << 16) + ('e' << 8) + 'v')	/* little-endian "rev" */

enum {
	REVEMU_SIGNATURE = IDREVHEADER,
	REVEMU_SIGNATURE2 = 0
};

enum {
	REVEMU_KEY_LEN = 32,
	REVEMU_BLOCK_SIZE = 32,
	REVEMU_SHA256_LEN = AUTHUM_CRYPTO_SHA256_DIGEST_SIZE
};

static const char *g_revemu_crypt_key = "_YOU_SERIOUSLY_NEED_TO_GET_LAID_";

authum_u32_t
qproto_rev_hash(const authum_char_t *str, authum_i32_t n)
{
	authum_u32_t hash = 0x4E67C6A7u;
	authum_i32_t cc;

	for (cc = *str; cc && n != 0; cc = *++str, --n) {
		hash ^= (hash >> 2) + (authum_u32_t)cc + 32u * hash;
	}

	return hash;
}

static void
revemu_finish_authorization(qproto_authdata_t *authdata, const authum_char_t *auth_str,
			    authum_usize_t auth_key_max_len, authum_bool_t strip_special_chars)
{
	authum_u32_t volume_id;
	authum_char_t hddsn[256];

	if (is_hddsn_number(auth_str)) {
		authdata->auth_key_kind = qproto_auth_key_kind_hddsn;

		if (strip_special_chars) {
			authdata->auth_key_len = strecpy(hddsn, auth_str, auth_key_max_len, " \\/-", '\0');
			auth_str = hddsn;
		} else {
			authum_usize_t l = (authum_usize_t)strlen(auth_str);
			authdata->auth_key_len = l < auth_key_max_len ? l : auth_key_max_len;
		}
	} else {
		authdata->auth_key_kind = qproto_auth_key_kind_volumeid;

		volume_id = (authum_u32_t)(strtoul(auth_str, authum_null, 10) & 0x7FFFFFFFu);
		authdata->auth_key_len = volume_id ? (authum_usize_t)sizeof(volume_id) : 0u; /* can't be zero */
		auth_str = (const authum_char_t *)&volume_id;
	}

	if (authdata->auth_key_len) {
		memcpy(authdata->auth_key, auth_str, authdata->auth_key_len);
		authdata->auth_key[authdata->auth_key_len] = '\0';

		authdata->steam_id = qproto_rev_hash(authdata->auth_key, -1) << 1;
	} else {
		authdata->steam_id = QPROTO_STEAM_ID_PENDING;
		authdata->auth_key_kind = qproto_auth_key_kind_other;
	}
}

typedef struct revemu_2013_ticket {
	uint32_t version;
	uint32_t hash;
	uint32_t rev_signature;
	uint32_t signature2;
	mini_steam_id_t steam_id;
	uint32_t expire_time;
	uint32_t not_creation_time;
	uint32_t unk20;
	uint32_t unk24;
	char encrypted_data[REVEMU_BLOCK_SIZE];
	char encrypted_key[REVEMU_BLOCK_SIZE];
	char digest[REVEMU_SHA256_LEN];
} revemu_2013_ticket_t;

typedef struct sc2009_ticket {
	uint32_t version;
	uint32_t hash;
	uint32_t rev_signature;
	uint32_t signature2;
	mini_steam_id_t steam_id;
	char encrypted_data[REVEMU_BLOCK_SIZE];
	char encrypted_key[REVEMU_BLOCK_SIZE];
	char digest[REVEMU_SHA256_LEN];
} sc2009_ticket_t;

typedef struct rev_ticket {
	uint32_t version;
	uint32_t hash;
	uint32_t rev_signature;
	uint32_t signature2;
	mini_steam_id_t steam_id;
	char ticket_buf[128];
} rev_ticket_t;

/*
 * Expanded from the former C++ template RevEmu2009to2013Authorize — two concrete
 * static functions for the two ticket layouts (RevEmu2013 vs SC2009).
 */
static int
revemu_2013_ticket_authorize(const revemu_2013_ticket_t *ticket, qproto_authdata_t *authdata,
			     authum_bool_t strip_special_chars)
{
	enum { VERSION = 0x53 };
	const authum_crypto_t *crypto;
	authum_crypto_rijndael_t h_crypt1;
	authum_crypto_rijndael_t h_crypt2;
	char decrypted_auth_key[REVEMU_KEY_LEN];
	char decrypted_auth_data[REVEMU_BLOCK_SIZE + 1];
	unsigned char digest[REVEMU_SHA256_LEN];
	uint32_t hash;
	uint32_t accid;

	if (ticket->version != VERSION || ticket->rev_signature != REVEMU_SIGNATURE || ticket->signature2 != REVEMU_SIGNATURE2)
		return 0;

	crypto = authum_host_crypto(&g_qproto_host);
	if (authum_null_eq(crypto))
		return 0;

	if (!authum_crypto_rijndael_init(crypto, &h_crypt1, (authum_ptr)(void *)g_revemu_crypt_key,
					 (authum_usize_t)REVEMU_KEY_LEN, authum_null, 0u,
					 (authum_usize_t)REVEMU_BLOCK_SIZE,
					 authum_crypto_rijndael_mode_ecb))
		return 0;

	if (!authum_crypto_rijndael_decrypt_block(crypto, &h_crypt1,
						  (authum_ptr)(void *)ticket->encrypted_key,
						  (authum_ptr)decrypted_auth_key))
		return 0;

	if (!authum_crypto_rijndael_init(crypto, &h_crypt2, (authum_ptr)decrypted_auth_key,
					 (authum_usize_t)REVEMU_KEY_LEN, authum_null, 0u,
					 (authum_usize_t)REVEMU_BLOCK_SIZE,
					 authum_crypto_rijndael_mode_ecb))
		return 0;

	if (!authum_crypto_rijndael_decrypt_block(crypto, &h_crypt2,
						  (authum_ptr)(void *)ticket->encrypted_data,
						  (authum_ptr)decrypted_auth_data))
		return 0;

	decrypted_auth_data[REVEMU_BLOCK_SIZE] = '\0';

	if (authum_crypto_sha_hash(crypto, authum_crypto_sha_kind_256,
				   (authum_ptr)decrypted_auth_data, (authum_usize_t)REVEMU_SHA256_LEN,
				   (authum_ptr)digest, (authum_usize_t)sizeof digest) !=
	    (authum_usize_t)REVEMU_SHA256_LEN)
		return 0;
	if (memcmp(digest, ticket->digest, REVEMU_SHA256_LEN) != 0)
		return 0;

	hash = qproto_rev_hash(decrypted_auth_data, -1);
	accid = mini_steam_id_get_account_id(&ticket->steam_id);

	if (hash != ticket->hash || (uint32_t)(hash << 1) != accid)
		return 0;

	revemu_finish_authorization(authdata, decrypted_auth_data,
				    (authum_usize_t)(sizeof decrypted_auth_data - 1u), strip_special_chars);
	return 1;
}

static int
sc2009_ticket_authorize(const sc2009_ticket_t *ticket, qproto_authdata_t *authdata,
			authum_bool_t strip_special_chars)
{
	enum { VERSION = 0x53 };
	const authum_crypto_t *crypto;
	authum_crypto_rijndael_t h_crypt1;
	authum_crypto_rijndael_t h_crypt2;
	char decrypted_auth_key[REVEMU_KEY_LEN];
	char decrypted_auth_data[REVEMU_BLOCK_SIZE + 1];
	unsigned char digest[REVEMU_SHA256_LEN];
	uint32_t hash;
	uint32_t accid;

	if (ticket->version != VERSION || ticket->rev_signature != REVEMU_SIGNATURE || ticket->signature2 != REVEMU_SIGNATURE2)
		return 0;

	crypto = authum_host_crypto(&g_qproto_host);
	if (authum_null_eq(crypto))
		return 0;

	if (!authum_crypto_rijndael_init(crypto, &h_crypt1, (authum_ptr)(void *)g_revemu_crypt_key,
					 (authum_usize_t)REVEMU_KEY_LEN, authum_null, 0u,
					 (authum_usize_t)REVEMU_BLOCK_SIZE,
					 authum_crypto_rijndael_mode_ecb))
		return 0;

	if (!authum_crypto_rijndael_decrypt_block(crypto, &h_crypt1,
						  (authum_ptr)(void *)ticket->encrypted_key,
						  (authum_ptr)decrypted_auth_key))
		return 0;

	if (!authum_crypto_rijndael_init(crypto, &h_crypt2, (authum_ptr)decrypted_auth_key,
					 (authum_usize_t)REVEMU_KEY_LEN, authum_null, 0u,
					 (authum_usize_t)REVEMU_BLOCK_SIZE,
					 authum_crypto_rijndael_mode_ecb))
		return 0;

	if (!authum_crypto_rijndael_decrypt_block(crypto, &h_crypt2,
						  (authum_ptr)(void *)ticket->encrypted_data,
						  (authum_ptr)decrypted_auth_data))
		return 0;

	decrypted_auth_data[REVEMU_BLOCK_SIZE] = '\0';

	if (authum_crypto_sha_hash(crypto, authum_crypto_sha_kind_256,
				   (authum_ptr)decrypted_auth_data, (authum_usize_t)REVEMU_SHA256_LEN,
				   (authum_ptr)digest, (authum_usize_t)sizeof digest) !=
	    (authum_usize_t)REVEMU_SHA256_LEN)
		return 0;
	if (memcmp(digest, ticket->digest, REVEMU_SHA256_LEN) != 0)
		return 0;

	hash = qproto_rev_hash(decrypted_auth_data, -1);
	accid = mini_steam_id_get_account_id(&ticket->steam_id);

	if (hash != ticket->hash || (uint32_t)(hash << 1) != accid)
		return 0;

	revemu_finish_authorization(authdata, decrypted_auth_data,
				    (authum_usize_t)(sizeof decrypted_auth_data - 1u), strip_special_chars);
	return 1;
}

qproto_client_auth_kind_t
qproto_revemu_2013_authorize(qproto_authdata_t *authdata)
{
	if (authdata->ticket_len < sizeof(revemu_2013_ticket_t))
		return qproto_client_auth_kind_unknown;

	/* RevEmu2013/SC2009 always strip special chars from HDDSN-formatted keys */
	return revemu_2013_ticket_authorize((const revemu_2013_ticket_t *)authdata->auth_ticket, authdata,
					    authum_bool_true)
		? qproto_client_auth_kind_revemu_2013 : qproto_client_auth_kind_unknown;
}

qproto_client_auth_kind_t
qproto_steamclient_2009_authorize(qproto_authdata_t *authdata)
{
	if (authdata->ticket_len < sizeof(sc2009_ticket_t))
		return qproto_client_auth_kind_unknown;

	return sc2009_ticket_authorize((const sc2009_ticket_t *)authdata->auth_ticket, authdata,
				       authum_bool_true)
		? qproto_client_auth_kind_steamclient_2009 : qproto_client_auth_kind_unknown;
}

qproto_client_auth_kind_t
qproto_revemu_authorize(qproto_authdata_t *authdata)
{
	enum { VERSION = 0x4A };
	rev_ticket_t *ticket;
	char saved;
	uint32_t hash;
	uint32_t accid;

	if (authdata->ticket_len < sizeof(rev_ticket_t))
		return qproto_client_auth_kind_unknown;

	/*
	 * Ticket is const, but we need to temporarily NUL a byte to hash the string
	 * safely - same keep-for-revert trick to avoid needing a scratch copy.
	 */
	ticket = (rev_ticket_t *)authdata->auth_ticket;
	if (ticket->version != VERSION || ticket->rev_signature != REVEMU_SIGNATURE || ticket->signature2 != REVEMU_SIGNATURE2)
		return qproto_client_auth_kind_unknown;

	saved = ticket->ticket_buf[sizeof(ticket->ticket_buf) - 1];
	ticket->ticket_buf[sizeof(ticket->ticket_buf) - 1] = '\0';

	hash = qproto_rev_hash(ticket->ticket_buf, -1);
	accid = mini_steam_id_get_account_id(&ticket->steam_id);

	if (hash != ticket->hash || (uint32_t)(hash << 1) != accid) {
		ticket->ticket_buf[sizeof(ticket->ticket_buf) - 1] = saved;
		return qproto_client_auth_kind_unknown;
	}

	revemu_finish_authorization(authdata, ticket->ticket_buf, sizeof(ticket->ticket_buf) - 1, 0);
	return qproto_client_auth_kind_revemu;
}

/* Ported from MultiEmulator's Emulators/OldRevEmu.h GenerateOldRevEmu(). */
#pragma pack(push, 1)
typedef struct old_rev_ticket {
	uint32_t header;	/* must be 0xFFFF */
	uint32_t steam_id_enc;	/* (steam_id ^ 0xC9710266) << 1 */
	uint16_t reserved;	/* must be 0 */
} old_rev_ticket_t;
#pragma pack(pop)

qproto_client_auth_kind_t
qproto_old_revemu_authorize(qproto_authdata_t *authdata)
{
	const old_rev_ticket_t *ticket;

	if (authdata->ticket_len != sizeof(old_rev_ticket_t))
		return qproto_client_auth_kind_unknown;

	ticket = (const old_rev_ticket_t *)authdata->auth_ticket;
	if (ticket->header != 0xFFFF || ticket->reserved != 0)
		return qproto_client_auth_kind_unknown;

	/*
	 * Inverse of the generator's (steamId ^ 0xC9710266) << 1. Note this is NOT
	 * (encoded >> 1) ^ key: left-shift distributes over XOR, so encoded actually
	 * equals (steamId << 1) ^ (key << 1), and undoing it means XOR-ing with the
	 * *shifted* key before shifting back - order matters here.
	 */
	authdata->steam_id = (ticket->steam_id_enc ^ (0xC9710266u << 1)) >> 1;
	authdata->auth_key_kind = qproto_auth_key_kind_other;
	authdata->auth_key_len = 0;

	return qproto_client_auth_kind_old_revemu;
}

qproto_client_auth_kind_t
qproto_setti_authorize(qproto_authdata_t *authdata)
{
	enum {
		TICKET_LEN = 0x300,
		SETTI_KEY1 = 0xD4CA7F7B,
		SETTI_KEY2 = 0xC7DB6023,
		SETTI_KEY3 = 0x6D6A2E1F,
		SETTI_KEY4 = 0xB4C43105,
	};
	const uint32_t *ikey;

	if (authdata->ticket_len != TICKET_LEN)
		return qproto_client_auth_kind_unknown;

	ikey = (const uint32_t *)authdata->auth_ticket;
	if (!(ikey[0] == SETTI_KEY1 || ikey[1] == SETTI_KEY2 || ikey[2] == SETTI_KEY3 || ikey[5] == SETTI_KEY4))
		return qproto_client_auth_kind_unknown;

	authdata->steam_id = QPROTO_STEAM_ID_LAN;
	authdata->auth_key_kind = qproto_auth_key_kind_other;
	authdata->auth_key_len = 0;
	return qproto_client_auth_kind_setti;
}

qproto_client_auth_kind_t
qproto_nosteam47_authorize(qproto_authdata_t *authdata)
{
	if (authdata->protocol != 47)
		return qproto_client_auth_kind_unknown;

	authdata->steam_id = QPROTO_STEAM_ID_LAN;
	authdata->auth_key_kind = qproto_auth_key_kind_other;
	authdata->auth_key_len = 0;
	return qproto_client_auth_kind_no_steam_47;
}

qproto_client_auth_kind_t
qproto_nosteam48_authorize(qproto_authdata_t *authdata)
{
	if (authdata->protocol != 48)
		return qproto_client_auth_kind_unknown;

	authdata->steam_id = QPROTO_STEAM_ID_LAN;
	authdata->auth_key_kind = qproto_auth_key_kind_other;
	authdata->auth_key_len = 0;
	return qproto_client_auth_kind_no_steam_48;
}

qproto_client_auth_kind_t
qproto_sxei_authorize(qproto_authdata_t *authdata)
{
	uint32_t sxe_id;

	if (!g_qproto_config.enable_sxei)
		return qproto_client_auth_kind_unknown;

	if (!authdata->sxei_hid_hex || !authdata->sxei_hid_hex[0])
		return qproto_client_auth_kind_unknown;

	if (sscanf(authdata->sxei_hid_hex, "%X", &sxe_id) != 1)
		return qproto_client_auth_kind_unknown;

	if (sxe_id == 0) {
		authdata->steam_id = QPROTO_STEAM_ID_PENDING;
		authdata->auth_key_kind = qproto_auth_key_kind_other;
		authdata->auth_key_len = 0;
	} else {
		authdata->steam_id = sxe_id << 1;
		authdata->auth_key_kind = qproto_auth_key_kind_sxeid;
		authdata->auth_key_len = sizeof(uint32_t);
		memcpy(authdata->auth_key, &sxe_id, sizeof(sxe_id));
	}

	return qproto_client_auth_kind_sxei;
}

qproto_client_auth_kind_t
qproto_vellum_authorize(qproto_authdata_t *authdata)
{
	const vellum_ticket_t *ticket;

	if (authdata->ticket_len != sizeof(vellum_ticket_t))
		return qproto_client_auth_kind_unknown;

	ticket = (const vellum_ticket_t *)authdata->auth_ticket;
	if (!vellum_ticket_valid(ticket, authdata->ticket_len))
		return qproto_client_auth_kind_unknown;

	authdata->steam_id = ticket->account_id;
	authdata->auth_key_kind = qproto_auth_key_kind_other;
	authdata->auth_key_len = ticket->ident_len;
	if (authdata->auth_key_len > QPROTO_MAX_AUTHKEY_LEN)
		authdata->auth_key_len = QPROTO_MAX_AUTHKEY_LEN;
	memcpy(authdata->auth_key, ticket->ident, authdata->auth_key_len);
	authdata->auth_key[authdata->auth_key_len] = '\0';
	return qproto_client_auth_kind_vellum;
}

qproto_client_auth_kind_t
qproto_authorize_client(qproto_authdata_t *authdata, authum_bool_t sc2009_rev_compat,
			authum_bool_t force_auth_version_2018_plus)
{
	qproto_client_auth_kind_t r;

	(void)sc2009_rev_compat;
	(void)force_auth_version_2018_plus;

	/*
	 * Order matches classic authorizer registration: userinfo-based checks first,
	 * then ticket formats from most to least specific, protocol-only catch-alls last.
	 */
	if ((r = qproto_sxei_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;
	if ((r = qproto_setti_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;

	if (g_qproto_config.enable_vellum && (r = qproto_vellum_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;
	if (g_qproto_config.enable_revemu && (r = qproto_revemu_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;
	if (g_qproto_config.enable_revemu_2013 && (r = qproto_revemu_2013_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;
	if (g_qproto_config.enable_sc2009 && (r = qproto_steamclient_2009_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;
	if (g_qproto_config.enable_old_revemu && (r = qproto_old_revemu_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;

	if ((r = qproto_nosteam47_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;
	if ((r = qproto_nosteam48_authorize(authdata)) != qproto_client_auth_kind_unknown) return r;

	return qproto_client_auth_kind_unknown;
}
