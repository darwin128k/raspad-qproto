#include "host_crypto.h"

namespace {

authum_host_aes_ecb_decrypt_block_fn g_aes_ecb_decrypt_block = nullptr;
authum_host_sha256_fn g_sha256 = nullptr;

} // namespace

void
qproto_host_crypto_bind(const authum_host_t *host)
{
	g_aes_ecb_decrypt_block =
		(host && host->aes_ecb_decrypt_block) ? host->aes_ecb_decrypt_block : nullptr;
	g_sha256 = (host && host->sha256) ? host->sha256 : nullptr;
}

int
qproto_host_crypto_ready(void)
{
	return (g_aes_ecb_decrypt_block && g_sha256) ? 1 : 0;
}

int
qproto_aes_ecb_decrypt_block(const void *key, unsigned key_len, const void *in, void *out,
                             unsigned block_len)
{
	if (!g_aes_ecb_decrypt_block)
		return 0;
	return g_aes_ecb_decrypt_block(key, key_len, in, out, block_len);
}

int
qproto_sha256(const void *data, unsigned len, void *out32)
{
	if (!g_sha256)
		return 0;
	return g_sha256(data, len, out32);
}
