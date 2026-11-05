#include <qproto/engine.h>
#include <qproto/logger.h>

#include <authum/symbol.h>
#include <authum/memory.h>

static const qproto_engine_layout_info_t g_classic = {
    qproto_engine_layout_classic,
    0x4a90u,
    4u,
    0xcu,  /* DWARF: network_userid @ 19088 */
    0x20u, /* netchan @ 0x1c + remote_address @ +4 */
    "classic (8684/2018-era)"};

static const qproto_engine_layout_info_t g_build10211 = {
    qproto_engine_layout_build10211,
    0x6200u,
    4u,
    0xcu,  /* DWARF: network_userid @ 25088 */
    0x20u, /* netchan still @ 0x1c + remote_address @ +4 */
    "build10211 (Oct 2024)"};

authum_ptr
qproto_engine_resolve(const authum_char_t *symbol, authum_i32_t *out_via_dynsym)
{
    authum_bool_t via_dynsym = authum_bool_false;
    authum_ptr address = authum_symbol_find_engine(symbol, &via_dynsym);

    if (!authum_null_eq(out_via_dynsym))
    {
        *out_via_dynsym = via_dynsym ? 1 : 0;
    }
    authum_logger_info(&g_qproto_logger, "engine resolve: %s %s", symbol,
                       address ? (via_dynsym ? "via dlsym" : "via .symtab") : "MISSING");
    return address;
}

const qproto_engine_layout_info_t *
qproto_engine_select_layout(qproto_engine_layout_t override_layout,
                            authum_i32_t resolved_via_dynsym)
{
    if (override_layout == qproto_engine_layout_classic)
    {
        return &g_classic;
    }
    if (override_layout == qproto_engine_layout_build10211)
    {
        return &g_build10211;
    }

    /* AUTO: dynsym hit ⇒ classic export style; symtab-only ⇒ 10211-style locals. */
    return resolved_via_dynsym ? &g_classic : &g_build10211;
}

const authum_char_t *
qproto_engine_layout_name(qproto_engine_layout_t layout)
{
    switch (layout)
    {
    case qproto_engine_layout_classic:
        return "classic";
    case qproto_engine_layout_build10211:
        return "10211";
    default:
        return "auto";
    }
}

authum_ptr
qproto_engine_find_windows(qproto_engine_layout_info_t *layout)
{
#if defined(_WIN32)
    static const authum_byte_t pattern[] = {
        0x55, 0x8b, 0xec, 0xa1, 0,    0,    0,    0,    0x85, 0xc0, 0x75, 0x04,
        0x33, 0xc0, 0x5d, 0xc3, 0x8b, 0x45, 0x10, 0x8b, 0x4d, 0x0c, 0x8b, 0x55,
        0x08, 0x50, 0x51, 0x52, 0xe8, 0,    0,    0,    0,    0x8b, 0xc8, 0xe8,
        0,    0,    0,    0,    0x25, 0xff, 0,    0,    0,    0x5d, 0xc3};
    static const authum_byte_t mask[] = {255, 255, 255, 255, 0,   0,   0,   0,   255, 255, 255, 255,
                                         255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                         255, 255, 255, 255, 255, 0,   0,   0,   0,   255, 255, 255,
                                         0,   0,   0,   0,   255, 255, 255, 255, 255, 255, 255};
    authum_usize_t count = 0;
    authum_byte_t *hit = authum_symbol_find_engine_pattern(pattern, mask, sizeof pattern, &count);
    if (count == 0u)
    {
        /* 2024: NotifyClientConnect is inlined into the cdecl wrapper. */
        static const authum_byte_t modern_pattern[] = {
            0x55, 0x8b, 0xec, 0xa1, 0,    0,    0,    0,    0x83, 0xec, 0x08, 0x85, 0xc0, 0x75,
            0x04, 0x8b, 0xe5, 0x5d, 0xc3, 0x53, 0x8b, 0x5d, 0x08, 0x85, 0xdb, 0x74, 0x79, 0x80,
            0x78, 0x04, 0,    0x74, 0x73, 0x81, 0x65, 0xfc, 0xff, 0xff, 0x0f, 0xff, 0x56, 0x57,
            0xc6, 0x45, 0xff, 0,    0x81, 0x65, 0xfc, 0,    0,    0xf0, 0xff, 0x68, 0,    0,
            0,    0,    0xc7, 0x83, 0,    0,    0,    0,    1,    0,    0,    0};
        static const authum_byte_t modern_mask[] = {
            255, 255, 255, 255, 0,   0,   0,   0,   255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 0,   0,   0,   0,   255, 255, 0,   0,   0,   0,   255, 255, 255, 255};
        hit = authum_symbol_find_engine_pattern(modern_pattern, modern_mask, sizeof modern_pattern,
                                                &count);
        if (count == 1u && hit)
        {
            authum_u32_t offset = 0;
            authum_memory_copy(&offset, hit + 60, sizeof offset);
            layout->layout = qproto_engine_layout_auto;
            layout->network_userid_offset = offset;
            layout->steam_id_offset = 8u;
            layout->client_ip_offset = 0x10u;
            layout->remote_address_offset = 0x20u;
            layout->name = "windows 2024 (from code)";
            return hit;
        }
    }
    if (!hit || count != 1u)
    {
        authum_logger_info(&g_qproto_logger, "Windows hook signature: expected one match, found %u",
                           (unsigned)count);
        return authum_null;
    }
    authum_i32_t rel = 0;
    authum_memory_copy(&rel, hit + 36, sizeof rel);
    const authum_byte_t *method = hit + 40 + rel;
    for (authum_usize_t i = 0; i + 10 <= 64; i++)
    {
        if (method[i] == 0xc7 && method[i + 1] >= 0x80 && method[i + 1] <= 0x87 &&
            method[i + 1] != 0x84 && method[i + 6] == 1 && method[i + 7] == 0 &&
            method[i + 8] == 0 && method[i + 9] == 0)
        {
            authum_u32_t offset = 0;
            authum_memory_copy(&offset, method + i + 2, sizeof offset);
            layout->layout = qproto_engine_layout_auto;
            layout->network_userid_offset = offset;
            layout->steam_id_offset = 8u;
            layout->client_ip_offset = 0x10u;
            layout->remote_address_offset = 0x20u;
            layout->name = "windows (from code)";
            return hit;
        }
    }
    authum_logger_info(
        &g_qproto_logger,
        "Windows hook signature found, but network_userid offset was not found in method");
#else
    (void)layout;
#endif
    return authum_null;
}
