#include <qproto/vellum/keystore.h>

#include <authum/file.h>
#include <authum/null.h>
#include <authum/path.h>

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
    authum_file_t file;
    authum_char_t line[VELLUM_PUBLIC_KEY_SIZE * 2 + 16];
    authum_usize_t length;
    authum_usize_t written = 0u;
    authum_usize_t i;
    authum_path_t path, parent;

    if (authum_null_eq(g_path))
    {
        return authum_bool_true;
    }
    if (!authum_path_set_cstr(&path, g_path) ||
        (authum_path_assign_parent(&parent, &path) && !authum_path_ensure_dir(&parent)))
    {
        return authum_bool_false;
    }
    /* "<id> <hex>" — the formatter knows no width, so the hex is written out. */
    length = authum_cstr_format(line, sizeof line, "%u ", (unsigned)account_id);
    if (length == 0u)
    {
        return authum_bool_false;
    }
    for (i = 0u; i < VELLUM_PUBLIC_KEY_SIZE; ++i)
    {
        const authum_char_t digits[] = "0123456789abcdef";

        line[length++] = digits[(public_key[i] >> 4) & 0x0fu];
        line[length++] = digits[public_key[i] & 0x0fu];
    }
    line[length++] = '\n';
    line[length] = '\0';

    authum_file_init(&file);
    if (!authum_file_open_cstr(&file, g_path, authum_file_mode_append))
    {
        return authum_bool_false;
    }
    if (!authum_file_write(&file, line, length, &written) || written != length)
    {
        authum_file_close(&file);
        return authum_bool_false;
    }
    authum_file_close(&file);
    return authum_bool_true;
}

/** The whole file in a buffer the caller frees; null when the read failed. */
static authum_char_t *
keystore_read_all(authum_file_t *file, authum_usize_t *out_size)
{
    authum_char_t *text = authum_null;
    authum_usize_t capacity = 0u;
    authum_usize_t size = 0u;

    for (;;)
    {
        authum_usize_t read = 0u;
        authum_char_t *grown;

        if (size == capacity)
        {
            capacity = capacity > 0u ? capacity * 2u : 4096u;
            grown = (authum_char_t *)realloc(text, capacity);
            if (authum_null_eq(grown))
            {
                free(text);
                return authum_null;
            }
            text = grown;
        }
        if (!authum_file_read(file, text + size, capacity - size, &read) || read == 0u)
        {
            break;
        }
        size += read;
    }
    if (authum_null_eq(text))
    {
        /* An empty file: the buffer is still needed to walk the lines. */
        text = (authum_char_t *)malloc(1u);
        if (authum_null_eq(text))
        {
            return authum_null;
        }
    }
    text[size] = '\0';
    *out_size = size;
    return text;
}

authum_bool_t
qproto_vellum_keystore_open(const authum_char_t *path)
{
    authum_file_t file;
    authum_char_t *text;
    authum_usize_t size = 0u;
    authum_usize_t start = 0u;
    authum_usize_t i;
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

    authum_file_init(&file);
    if (!authum_file_open_cstr(&file, path, authum_file_mode_read))
    {
        return authum_bool_true; /* first start: nothing pinned yet */
    }
    text = keystore_read_all(&file, &size);
    authum_file_close(&file);
    if (authum_null_eq(text))
    {
        return authum_bool_false;
    }
    for (i = 0u; i <= size; ++i)
    {
        if (i != size && text[i] != '\n')
        {
            continue;
        }
        text[i] = '\0';
        if (i > start && text[start] != '#' && keystore_parse_line(text + start, &account_id, public_key))
        {
            /* First pin wins, same as at runtime. */
            if (authum_null_eq(keystore_find(account_id)) && !keystore_push(account_id, public_key))
            {
                free(text);
                return authum_bool_false;
            }
        }
        start = i + 1u;
    }
    free(text);
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
