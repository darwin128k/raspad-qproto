#ifndef QPROTO_ENGINE_H
#define QPROTO_ENGINE_H

#include <stdint.h>

/*
 * HLDS engine_i486.so layouts qproto has been measured against (DWARF).
 * classic: Aug 2018 / build 8684-era — Steam_NotifyClientConnect is a dynamic export,
 *          client_t::network_userid @ 0x4a90.
 * build10211: Oct 2024 build 10211 — same symbols exist but are local (.symtab only),
 *          client_t::network_userid @ 0x6200. netchan.remote_address stays @ +0x20.
 */
typedef enum qproto_engine_layout
{
    qproto_engine_layout_auto = 0,
    qproto_engine_layout_classic = 1,
    qproto_engine_layout_build10211 = 2,
} qproto_engine_layout_t;

typedef struct qproto_engine_layout_info
{
    qproto_engine_layout_t layout;
    uintptr_t network_userid_offset;
    uintptr_t remote_address_offset; /* client_t::netchan.remote_address */
    const char *name;
} qproto_engine_layout_info_t;

/*
 * Resolve a symbol inside the already-loaded engine_i486.so through
 * authum_symbol_find_engine (dlsym, then the on-disk .symtab for build 10211's
 * locals) and log where it came from. Sets *out_via_dynsym when non-null.
 */
void *
qproto_engine_resolve(const char *symbol, int *out_via_dynsym);

/* Pick layout from config override or from how Resolve found the primary hook symbol. */
const qproto_engine_layout_info_t *
qproto_engine_select_layout(qproto_engine_layout_t override_layout, int resolved_via_dynsym);

const char *
qproto_engine_layout_name(qproto_engine_layout_t layout);

#endif /* QPROTO_ENGINE_H */
