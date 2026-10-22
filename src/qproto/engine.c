#include <qproto/engine.h>
#include <qproto/logger.h>

#include <authum/symbol.h>

static const qproto_engine_layout_info_t g_classic = {
    qproto_engine_layout_classic, 0x4a90u, /* DWARF: network_userid @ 19088 */
    0x20u,                                 /* netchan @ 0x1c + remote_address @ +4 */
    "classic (8684/2018-era)"};

static const qproto_engine_layout_info_t g_build10211 = {
    qproto_engine_layout_build10211, 0x6200u, /* DWARF: network_userid @ 25088 */
    0x20u,                                    /* netchan still @ 0x1c + remote_address @ +4 */
    "build10211 (Oct 2024)"};

void *
qproto_engine_resolve(const char *symbol, int *out_via_dynsym)
{
    authum_bool_t via_dynsym = authum_bool_false;
    authum_ptr address = authum_symbol_find_engine(symbol, &via_dynsym);

    if (out_via_dynsym)
    {
        *out_via_dynsym = via_dynsym ? 1 : 0;
    }
    authum_logger_info(&g_qproto_logger, "engine resolve: %s %s @ %p", symbol,
                       address ? (via_dynsym ? "via dlsym" : "via .symtab") : "MISSING", address);
    return address;
}

const qproto_engine_layout_info_t *
qproto_engine_select_layout(qproto_engine_layout_t override_layout, int resolved_via_dynsym)
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

const char *
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
