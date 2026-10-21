#ifndef QPROTO_VELLUM_KEYSTORE_H
#define QPROTO_VELLUM_KEYSTORE_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

#include <qproto/vellum/ticket.h>

/*
 * Vellum SteamID -> public key pins (trust on first use). The first key seen
 * for an account id owns it; a later ticket with the same id but another key
 * is a forgery (or a 31-bit id collision) and is refused.
 *
 * File: one "<account_id> <64 hex public key>" per line, '#' comments.
 * New pins are appended as they happen. Engine-free (stdio only).
 */

enum qproto_vellum_bind
{
    qproto_vellum_bind_known = 0,      /* id already pinned to this key */
    qproto_vellum_bind_new = 1,        /* first sight — pinned and saved */
    qproto_vellum_bind_new_unsaved = 2, /* pinned in memory, file append failed */
    qproto_vellum_bind_conflict = 3,   /* id pinned to a different key */
    qproto_vellum_bind_error = 4,      /* out of memory / bad args */
};
typedef enum qproto_vellum_bind qproto_vellum_bind_t;

/* Load pins from @p path (missing file = empty). A null path keeps pins in memory only. */
authum_bool_t
qproto_vellum_keystore_open(const authum_char_t *path);

void
qproto_vellum_keystore_close(void);

qproto_vellum_bind_t
qproto_vellum_keystore_bind(authum_u32_t account_id,
                            const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE]);

authum_usize_t
qproto_vellum_keystore_count(void);

#endif /* QPROTO_VELLUM_KEYSTORE_H */
