#ifndef QPROTO_UTILS_H
#define QPROTO_UTILS_H

#include <stddef.h>
#include <stdint.h>

/* Taken from classic HLDS auth: utils sources (GPLv3) - no engine dependency in these. */
size_t strecpy(char *dest, const char *src, size_t maxlen, const char *except_chars, char rep_char);
int is_valid_id(uint32_t auth_id);
int is_hddsn_number(const char *authstring);
int is_valid_hddsn_number(const void *data, size_t maxlen);

#endif /* QPROTO_UTILS_H */
