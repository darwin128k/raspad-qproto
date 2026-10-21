#include <qproto/vellum/keystore.h>

#include <authum/null.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct qproto_vellum_pin
{
    authum_u32_t account_id;
    authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE];
} qproto_vellum_pin_t;

static qproto_vellum_pin_t *g_pins;
static authum_usize_t g_pin_count;
static authum_usize_t g_pin_capacity;
static authum_char_t *g_path;

static authum_bool_t
keystore_push(authum_u32_t account_id, const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    qproto_vellum_pin_t *grown;
    authum_usize_t capacity;

    if (g_pin_count == g_pin_capacity)
    {
        capacity = g_pin_capacity > 0u ? g_pin_capacity * 2u : 64u;
        grown = (qproto_vellum_pin_t *)realloc(g_pins, (size_t)capacity * sizeof *g_pins);
        if (authum_null_eq(grown))
        {
            return authum_bool_false;
        }
        g_pins = grown;
        g_pin_capacity = capacity;
    }
    g_pins[g_pin_count].account_id = account_id;
    memcpy(g_pins[g_pin_count].public_key, public_key, VELLUM_PUBLIC_KEY_SIZE);
    ++g_pin_count;
    return authum_bool_true;
}

static const qproto_vellum_pin_t *
keystore_find(authum_u32_t account_id)
{
    authum_usize_t i;

    for (i = 0u; i < g_pin_count; ++i)
    {
        if (g_pins[i].account_id == account_id)
        {
            return &g_pins[i];
        }
    }
    return authum_null;
}

static authum_bool_t
keystore_parse_line(const authum_char_t *line, authum_u32_t *account_id,
                    authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    unsigned long id;
    unsigned int byte;
    char hex[VELLUM_PUBLIC_KEY_SIZE * 2 + 1];
    int i;

    if (sscanf(line, "%lu %64s", &id, hex) != 2 || strlen(hex) != VELLUM_PUBLIC_KEY_SIZE * 2)
    {
        return authum_bool_false;
    }
    for (i = 0; i < VELLUM_PUBLIC_KEY_SIZE; ++i)
    {
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
        {
            return authum_bool_false;
        }
        public_key[i] = (authum_byte_t)byte;
    }
    *account_id = (authum_u32_t)id;
    return authum_bool_true;
}

static authum_bool_t
keystore_append(authum_u32_t account_id, const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    FILE *f;
    int i;
    int ok;

    if (authum_null_eq(g_path))
    {
        return authum_bool_true;
    }
    f = fopen(g_path, "a");
    if (authum_null_eq(f))
    {
        return authum_bool_false;
    }
    ok = fprintf(f, "%u ", (unsigned)account_id) > 0;
    for (i = 0; i < VELLUM_PUBLIC_KEY_SIZE && ok; ++i)
    {
        ok = fprintf(f, "%02x", (unsigned)public_key[i]) > 0;
    }
    ok = ok && fputc('\n', f) != EOF;
    ok = (fclose(f) == 0) && ok;
    return ok ? authum_bool_true : authum_bool_false;
}

authum_bool_t
qproto_vellum_keystore_open(const authum_char_t *path)
{
    FILE *f;
    char line[256];
    authum_u32_t account_id;
    authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE];
    size_t len;

    qproto_vellum_keystore_close();
    if (authum_null_eq(path))
    {
        return authum_bool_true;
    }

    len = strlen(path);
    g_path = (authum_char_t *)malloc(len + 1u);
    if (authum_null_eq(g_path))
    {
        return authum_bool_false;
    }
    memcpy(g_path, path, len + 1u);

    f = fopen(path, "r");
    if (authum_null_eq(f))
    {
        return authum_bool_true; /* first start: nothing pinned yet */
    }
    while (fgets(line, sizeof line, f))
    {
        if (line[0] == '#' || !keystore_parse_line(line, &account_id, public_key))
        {
            continue;
        }
        /* First pin wins, same as at runtime. */
        if (authum_null_eq(keystore_find(account_id)) && !keystore_push(account_id, public_key))
        {
            fclose(f);
            return authum_bool_false;
        }
    }
    fclose(f);
    return authum_bool_true;
}

void
qproto_vellum_keystore_close(void)
{
    free(g_pins);
    free(g_path);
    g_pins = authum_null;
    g_path = authum_null;
    g_pin_count = 0u;
    g_pin_capacity = 0u;
}

qproto_vellum_bind_t
qproto_vellum_keystore_bind(authum_u32_t account_id,
                            const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    const qproto_vellum_pin_t *pin;

    if (authum_null_eq(public_key))
    {
        return qproto_vellum_bind_error;
    }
    pin = keystore_find(account_id);
    if (!authum_null_eq(pin))
    {
        return memcmp(pin->public_key, public_key, VELLUM_PUBLIC_KEY_SIZE) == 0
                   ? qproto_vellum_bind_known
                   : qproto_vellum_bind_conflict;
    }
    if (!keystore_push(account_id, public_key))
    {
        return qproto_vellum_bind_error;
    }
    return keystore_append(account_id, public_key) ? qproto_vellum_bind_new
                                                   : qproto_vellum_bind_new_unsaved;
}

authum_usize_t
qproto_vellum_keystore_count(void)
{
    return g_pin_count;
}
