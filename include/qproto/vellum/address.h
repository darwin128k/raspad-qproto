#ifndef QPROTO_VELLUM_ADDRESS_H
#define QPROTO_VELLUM_ADDRESS_H

#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

/* Most addresses a server can list in `vellum_server_ip`. */
#define QPROTO_VELLUM_MAX_SERVER_IPS 4u

/*
 * Parse "1.2.3.4, 5.6.7.8" into Steam host order (1.2.3.4 -> 0x01020304).
 * Entries that are not a public-looking dotted quad (garbage, 0.0.0.0,
 * 127.x, "localhost") are skipped. Returns how many landed in @p out.
 */
authum_usize_t
qproto_vellum_parse_ip_list(const authum_char_t *text, authum_u32_t *out, authum_usize_t max);

#endif /* QPROTO_VELLUM_ADDRESS_H */
