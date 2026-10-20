#ifndef QPROTO_BANS_H
#define QPROTO_BANS_H

#include <stdint.h>
#include <stddef.h>

/*
 * Bans by raw auth key (HDD serial / volume id / sXe Injected hardware id) - the
 * value qproto derives an emulated SteamID from, not the SteamID itself.
 */

void qproto_bans_load(void);
int qproto_bans_is_banned(const uint8_t *key, size_t len);
int qproto_bans_add(const uint8_t *key, size_t len);
int qproto_bans_remove(const uint8_t *key, size_t len);
int qproto_bans_parse_hex_line(const char *line, uint8_t *out_key, size_t *out_len);

#endif /* QPROTO_BANS_H */
