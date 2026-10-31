#ifndef QPROTO_UTILS_H
#define QPROTO_UTILS_H

#include <authum/byte.h>
#include <authum/char.h>
#include <authum/ptr.h>
#include <authum/size.h>

/* Taken from classic HLDS auth: utils sources (GPLv3) - no engine dependency in these. */
authum_usize_t
strecpy(authum_char_t *dest, const authum_char_t *src, authum_usize_t maxlen,
        const authum_char_t *except_chars, authum_char_t rep_char);
int
is_valid_id(authum_u32_t auth_id);
int
is_hddsn_number(const authum_char_t *authstring);
int
is_valid_hddsn_number(authum_cptr data, authum_usize_t maxlen);

#endif /* QPROTO_UTILS_H */
