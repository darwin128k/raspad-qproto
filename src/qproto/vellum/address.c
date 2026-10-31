#include <qproto/vellum/address.h>

#include <authum/bool.h>
#include <authum/cstr.h>
#include <authum/null.h>

/* One dotted quad at *p; advances *p past it. */
static authum_bool_t
parse_ipv4(const authum_char_t **p, authum_u32_t *out)
{
    const authum_char_t *s = *p;
    authum_u32_t ip = 0u;

    for (authum_u32_t i = 0u; i < 4u; ++i)
    {
        authum_u32_t part = 0u;
        authum_usize_t used = 0u;

        if (*s == '+')
        {
            ++s;
            ++used; /* a sign is part of what the number took */
        }
        if (!authum_char_is_digit(*s))
        {
            return authum_bool_false;
        }
        while (authum_char_is_digit(*s))
        {
            part = part * 10u + (authum_u32_t)(*s - '0');
            ++s;
            ++used;
            if (used > 3u)
            {
                return authum_bool_false; /* more than three digits */
            }
        }
        if (part > 255u)
        {
            return authum_bool_false;
        }
        ip = (ip << 8) | part;
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
        if (*text == ',' || authum_char_is_space(*text))
        {
            ++text;
            continue;
        }
        if (parse_ipv4(&text, &ip) &&
            (*text == '\0' || *text == ',' || authum_char_is_space(*text)) && ip != 0u &&
            (ip >> 24) != 127u)
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
