#include <qproto/vellum/keystore.h>

#include <authum/cstr.h>
#include <authum/file.h>
#include <authum/memory.h>
#include <authum/null.h>
#include <authum/path.h>

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
    if (g_pin_count == g_pin_capacity)
    {
        authum_usize_t capacity = g_pin_capacity > 0u ? g_pin_capacity * 2u : 64u;
        qproto_vellum_pin_t *grown = (qproto_vellum_pin_t *)authum_memory_realloc(
            g_pins, g_pin_capacity * sizeof *g_pins, capacity * sizeof *g_pins);

        if (authum_null_eq(grown))
        {
            return authum_bool_false;
        }
        g_pins = grown;
        g_pin_capacity = capacity;
    }
    g_pins[g_pin_count].account_id = account_id;
    authum_memory_copy(g_pins[g_pin_count].public_key, public_key, VELLUM_PUBLIC_KEY_SIZE);
    ++g_pin_count;
    return authum_bool_true;
}

static const qproto_vellum_pin_t *
keystore_find(authum_u32_t account_id)
{
    for (authum_usize_t i = 0u; i < g_pin_count; ++i)
    {
        if (g_pins[i].account_id == account_id)
        {
            return &g_pins[i];
        }
    }
    return authum_null;
}

/* One "<account_id> <64 hex characters>" line. */
static authum_bool_t
keystore_parse_line(const authum_char_t *line, authum_u32_t *account_id,
                    authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    authum_char_t id_text[16];
    const authum_char_t *key_text;
    authum_usize_t id_size = 0u;
    authum_usize_t hex_size = 0u;
    authum_usize_t key_start;

    /* The id: the number in front of the first space. */
    while (line[id_size] != '\0' && !authum_char_is_space(line[id_size]))
    {
        if (id_size + 1u >= sizeof id_text)
        {
            return authum_bool_false;
        }
        ++id_size;
    }
    if (id_size == 0u)
    {
        return authum_bool_false;
    }
    authum_memory_copy(id_text, line, id_size);
    id_text[id_size] = '\0';
    if (!authum_cstr_parse_u32(id_text, account_id))
    {
        return authum_bool_false;
    }

    /* The key: the hexadecimal characters after the space. */
    key_start = id_size;
    while (line[key_start] != '\0' && authum_char_is_space(line[key_start]))
    {
        ++key_start;
    }
    key_text = line + key_start;
    while (key_text[hex_size] != '\0' && !authum_char_is_space(key_text[hex_size]))
    {
        ++hex_size;
    }
    if (hex_size < (authum_usize_t)VELLUM_PUBLIC_KEY_SIZE * 2u)
    {
        return authum_bool_false;
    }
    return authum_cstr_parse_hex_bytes(key_text, public_key, VELLUM_PUBLIC_KEY_SIZE);
}

static authum_bool_t
keystore_append(authum_u32_t account_id, const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    if (authum_null_eq(g_path))
    {
        return authum_bool_true;
    }

    {
        authum_path_t path;
        authum_path_t parent;

        if (!authum_path_set_cstr(&path, g_path) ||
            (authum_path_assign_parent(&parent, &path) && !authum_path_ensure_dir(&parent)))
        {
            return authum_bool_false;
        }
    }

    authum_char_t line[VELLUM_PUBLIC_KEY_SIZE * 2 + 16];

    /* "<id> <hex>" — the formatter has no width, the hex brick writes the key. */
    authum_usize_t length = authum_cstr_format(line, sizeof line, "%u ", (unsigned)account_id);

    if (length == 0u)
    {
        return authum_bool_false;
    }

    authum_usize_t hex_length = authum_cstr_format_hex_bytes(
        public_key, VELLUM_PUBLIC_KEY_SIZE, line + length, sizeof line - length, authum_bool_false);

    if (hex_length != (authum_usize_t)VELLUM_PUBLIC_KEY_SIZE * 2u)
    {
        return authum_bool_false;
    }
    length += hex_length;
    line[length++] = '\n';
    line[length] = '\0';

    authum_file_t file;
    authum_usize_t written = 0u;

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

        if (size == capacity)
        {
            authum_usize_t old_capacity = capacity;
            authum_char_t *grown;

            capacity = capacity > 0u ? capacity * 2u : 4096u;
            grown = (authum_char_t *)authum_memory_realloc(text, old_capacity, capacity);
            if (authum_null_eq(grown))
            {
                authum_memory_free(text);
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
        text = (authum_char_t *)authum_memory_alloc(1u);
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

    qproto_vellum_keystore_close();
    if (authum_null_eq(path))
    {
        return authum_bool_true;
    }

    {
        authum_usize_t len = authum_cstr_len(path);

        g_path = (authum_char_t *)authum_memory_alloc(len + 1u);
        if (authum_null_eq(g_path))
        {
            return authum_bool_false;
        }
        authum_memory_copy(g_path, path, len + 1u);
    }

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
        authum_u32_t account_id;
        authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE];

        if (i != size && text[i] != '\n')
        {
            continue;
        }
        text[i] = '\0';
        if (i > start && text[start] != '#' &&
            keystore_parse_line(text + start, &account_id, public_key))
        {
            /* First pin wins, same as at runtime. */
            if (authum_null_eq(keystore_find(account_id)) && !keystore_push(account_id, public_key))
            {
                authum_memory_free(text);
                return authum_bool_false;
            }
        }
        start = i + 1u;
    }
    authum_memory_free(text);
    return authum_bool_true;
}

void
qproto_vellum_keystore_close(void)
{
    authum_memory_free(g_pins);
    authum_memory_free(g_path);
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
        return authum_memory_is_equal(pin->public_key, public_key, VELLUM_PUBLIC_KEY_SIZE)
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
