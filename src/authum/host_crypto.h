#pragma once

#include <authum/host.h>

#ifdef __cplusplus
extern "C" {
#endif

void qproto_host_crypto_bind(const authum_host_t *host);

/** 1 if both AES-ECB decrypt and SHA-256 are bound. */
int qproto_host_crypto_ready(void);

/**
 * ECB Rijndael decrypt of one block via Authum/lh.
 * @return 1 on success, 0 on failure / unbound.
 */
int qproto_aes_ecb_decrypt_block(const void *key, unsigned key_len, const void *in, void *out,
                                 unsigned block_len);

/**
 * One-shot SHA-256 into @p out32 (32 bytes) via Authum/lh.
 * @return 1 on success, 0 on failure / unbound.
 */
int qproto_sha256(const void *data, unsigned len, void *out32);

#ifdef __cplusplus
}
#endif
