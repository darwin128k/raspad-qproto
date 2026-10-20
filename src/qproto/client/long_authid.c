#include <qproto/client/long_authid.h>

#include <authum/null.h>

#include <string.h>

authum_bool_t
qproto_client_long_authid(const authum_crypto_t *crypto, qproto_client_info_t *info)
{
	authum_byte_t fallback[sizeof(authum_u32_t) * 2u];
	authum_byte_t digest[AUTHUM_CRYPTO_SHA256_DIGEST_SIZE];
	const authum_byte_t *data;
	authum_usize_t len;
	authum_u32_t kind;

	if (authum_null_eq(crypto) || authum_null_eq(info))
		return authum_bool_false;

	if (info->auth_key_len > 0u) {
		data = info->auth_key;
		len = info->auth_key_len;
	} else {
		kind = (authum_u32_t)info->auth_kind;
		memcpy(fallback, &kind, sizeof kind);
		memcpy(fallback + sizeof kind, &info->steam_id, sizeof info->steam_id);
		data = fallback;
		len = (authum_usize_t)sizeof fallback;
	}

	if (authum_crypto_sha_hash(crypto, authum_crypto_sha_kind_256, (authum_ptr)(void *)data, len,
				   (authum_ptr)digest, (authum_usize_t)sizeof digest) !=
	    AUTHUM_CRYPTO_SHA256_DIGEST_SIZE)
		return authum_bool_false;
	memcpy(info->long_authid, digest, sizeof info->long_authid);
	return authum_bool_true;
}
