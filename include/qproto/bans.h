#ifndef QPROTO_BANS_H
#define QPROTO_BANS_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

/*
 * Bans by raw auth key (HDD serial / volume id / sXe Injected hardware id) —
 * the value qproto derives an emulated SteamID from, not the SteamID itself.
 */

void qproto_bans_load(void);
authum_bool_t qproto_bans_is_banned(const authum_byte_t *key, authum_usize_t len);
authum_bool_t qproto_bans_add(const authum_byte_t *key, authum_usize_t len);
authum_bool_t qproto_bans_remove(const authum_byte_t *key, authum_usize_t len);
authum_bool_t qproto_bans_parse_hex_line(const authum_char_t *line, authum_byte_t *out_key,
					 authum_usize_t *out_len);

#endif /* QPROTO_BANS_H */
