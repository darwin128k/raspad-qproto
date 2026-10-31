#include <qproto/utils.h>

#include <authum/char.h>
#include <authum/cstr.h>
#include <authum/memory.h>
#include <authum/null.h>

/* Taken from classic HLDS auth: utils.cpp (GPLv3), verbatim logic. */

authum_usize_t
strecpy(authum_char_t *dest, const authum_char_t *src, authum_usize_t maxlen,
        const authum_char_t *except_chars, authum_char_t rep_char)
{
    authum_usize_t len = 0;

    for (; *src && len < maxlen; src++)
    {
        authum_char_t c = *src;

        if (!authum_null_eq(authum_cstr_find_char(except_chars, c)))
        {
            if (!rep_char)
            {
                continue;
            }

            c = rep_char;
        }

        len++;
        *dest++ = c;
    }

    *dest = '\0';
    return len;
}

int
is_valid_id(authum_u32_t auth_id)
{
    const authum_u32_t steam_id_pending = 1;

    return auth_id > steam_id_pending;
}

int
is_hddsn_number(const authum_char_t *authstring)
{
    const authum_char_t *c;

    for (c = authstring; *c; c++)
    {
        /* HDDSNs have spaces or letters */
        if (!authum_char_is_digit(*c))
        {
            return 1;
        }
    }

    if (*authstring == '\0')
    {
        return 0; /* no digits at all: a volume id, not an HDDSN */
    }

    authum_u32_t number;

    if (!authum_cstr_parse_u32(authstring, &number))
    {
        return 1; /* more than 32 bits: an SSD serial */
    }
    return number >= 0xffffffffu ? 1 : 0; /* SSD */
}

/*
 * See classic comment: some NVMe SSDs report this fixed bogus serial via a
 * Windows API quirk (Storage Descriptor path instead of the real driver call);
 * treat it as invalid rather than minting a colliding SteamID from it.
 */
static const authum_char_t *g_bad_hddsn_number = "0000_0000_0000_0000_0000_0100_0";

int
is_valid_hddsn_number(authum_cptr data, authum_usize_t maxlen)
{
    authum_usize_t n = authum_cstr_len(g_bad_hddsn_number);

    if (maxlen < n)
    {
        n = maxlen;
    }
    return !authum_memory_is_equal(data, g_bad_hddsn_number, n);
}
