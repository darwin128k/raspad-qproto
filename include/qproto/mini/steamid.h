#ifndef QPROTO_MINISTEAMID_H
#define QPROTO_MINISTEAMID_H

#include <authum/byte.h>

/*
 * Minimal stand-in for Valve's CSteamID (steamclientpublic.h), which full Steam SDK
 * headers pull in wholesale from the Steam SDK. We only need the account id, and per
 * the real struct's layout (public/steam/steamclientpublic.h, union SteamID_t /
 * SteamIDComponent_t on a little-endian target): a plain 64-bit value whose low 32
 * bits are the account ID. Ticket structs sent by RevEmu-family emulators embed this
 * same 8-byte layout, so this must stay bit-compatible even though it doesn't pull
 * in the rest of the Steam SDK.
 */
typedef struct mini_steam_id
{
    authum_u64_t bits;
} mini_steam_id_t;

static inline authum_u32_t
mini_steam_id_get_account_id(const mini_steam_id_t *id)
{
    return (authum_u32_t)(id->bits & 0xFFFFFFFFu);
}

#endif /* QPROTO_MINISTEAMID_H */
