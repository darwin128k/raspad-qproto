#include "qproto/qproto_utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

/* Taken from classic HLDS auth: utils.cpp (GPLv3), verbatim logic. */

size_t
strecpy(char *dest, const char *src, size_t maxlen, const char *except_chars, char rep_char)
{
	size_t len = 0;

	for (; *src && len < maxlen; src++) {
		char c = *src;
		if (strchr(except_chars, c)) {
			if (!rep_char)
				continue;

			c = rep_char;
		}

		len++;
		*dest++ = c;
	}

	*dest = '\0';
	return len;
}

int
is_valid_id(uint32_t auth_id)
{
	const uint32_t steam_id_pending = 1;
	return auth_id > steam_id_pending;
}

int
is_hddsn_number(const char *authstring)
{
	const char *c;
	for (c = authstring; *c; c++) {
		/* HDDSNs have spaces or letters */
		if (*c < '0' || *c > '9')
			return 1;
	}

	return strtoull(authstring, NULL, 10) >= UINT32_MAX; /* SSD */
}

/*
 * See classic comment: some NVMe SSDs report this fixed bogus serial via a
 * Windows API quirk (Storage Descriptor path instead of the real driver call);
 * treat it as invalid rather than minting a colliding SteamID from it.
 */
static const char *g_bad_hddsn_number = "0000_0000_0000_0000_0000_0100_0";

int
is_valid_hddsn_number(const void *data, size_t maxlen)
{
	size_t n = strlen(g_bad_hddsn_number);
	if (maxlen < n)
		n = maxlen;
	return memcmp(data, g_bad_hddsn_number, n) != 0;
}
