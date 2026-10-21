#include <qproto/vellum/address.h>

#include <authum/bool.h>
#include <authum/null.h>

#include <ctype.h>
#include <stdlib.h>

/* One dotted quad at *p; advances *p past it. */
static authum_bool_t
parse_ipv4(const authum_char_t **p, authum_u32_t *out)
{
    const authum_char_t *s = *p;
    authum_u32_t ip = 0u;
    unsigned long part;
    char *end;
    int i;

    for (i = 0; i < 4; ++i)
    {
        if (!isdigit((unsigned char)*s))
        {
            return authum_bool_false;
        }
        part = strtoul(s, &end, 10);
        if (part > 255ul || end - s > 3)
        {
            return authum_bool_false;
        }
        ip = (ip << 8) | (authum_u32_t)part;
        s = end;
        if (i < 3)
        {
            if (*s != '.')
            {
                return authum_bool_false;
            }
            ++s;
        }
    }
    *p = s;
    *out = ip;
    return authum_bool_true;
}

authum_usize_t
qproto_vellum_parse_ip_list(const authum_char_t *text, authum_u32_t *out, authum_usize_t max)
{
    authum_usize_t count = 0u;
    authum_u32_t ip;

    if (authum_null_eq(text) || authum_null_eq(out))
    {
        return 0u;
    }
    while (*text != '\0' && count < max)
    {
        if (*text == ',' || isspace((unsigned char)*text))
        {
            ++text;
            continue;
        }
        if (parse_ipv4(&text, &ip) && (*text == '\0' || *text == ',' || isspace((unsigned char)*text)) &&
            ip != 0u && (ip >> 24) != 127u)
        {
            out[count++] = ip;
            continue;
        }
        while (*text != '\0' && *text != ',')
        {
            ++text;
        }
    }
    return count;
}
