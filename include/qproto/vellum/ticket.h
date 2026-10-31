#ifndef QPROTO_VELLUM_TICKET_H
#define QPROTO_VELLUM_TICKET_H

#include <authum/byte.h>
#include <authum/char.h>
#include <authum/memory.h>
#include <authum/null.h>
#include <authum/ptr.h>
#include <authum/size.h>

/*
 * Vellum ticket v2 — GoldSrc connect blob emitted by raspad-revloader's
 * steamclient and parsed here as qproto_client_auth_kind_vellum.
 *
 * The client keeps an Ed25519 key pair in the user profile and signs every
 * connect: the signature covers the server address the client dialled and
 * the client's clock, so a ticket collected by one server is useless on
 * another. The SteamID is derived from the public key; the server pins
 * SteamID -> key on first sight (vellum/keystore.h). Nothing about the
 * player's machine (hostname, disk serial) is sent.
 *
 * v1 (64 bytes, FNV checksum, plaintext "HOSTNAME-SERIAL") carried no secret
 * and is rejected — see vellum_ticket_is_v1().
 *
 * Header only, no crypto: the signature is checked by the caller
 * (<authum/crypto/ed25519.h> here, Monocypher in the client).
 * Keep wire layout in sync with raspad-revloader/src/common/vellum_ticket.h.
 */

#define VELLUM_TICKET_MAGIC 0x4D4C4C56u /* 'VLLM' little-endian */
#define VELLUM_TICKET_VERSION 2
#define VELLUM_PUBLIC_KEY_SIZE 32
#define VELLUM_SIGNATURE_SIZE 64

#define VELLUM_TICKET_V1_VERSION 1
#define VELLUM_TICKET_V1_SIZE 64u

#pragma pack(push, 1)
typedef struct vellum_ticket
{
    authum_u32_t magic;
    unsigned short version;     /* 16 bits on the wire, no Authum type for it */
    unsigned short flags;       /* 0 — reserved */
    authum_u32_t server_ip;     /* as dialled, 1.2.3.4 -> 0x01020304 (Steam host order) */
    unsigned short server_port; /* host order */
    unsigned short reserved;    /* 0 */
    authum_u64_t timestamp;     /* client clock, UTC seconds since 1970 */
    authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE];
    authum_byte_t signature[VELLUM_SIGNATURE_SIZE]; /* Ed25519 over every byte before it */
} vellum_ticket_t;
#pragma pack(pop)

/* Bytes covered by the signature: the whole ticket up to `signature`. */
#define VELLUM_TICKET_SIGNED_SIZE (sizeof(vellum_ticket_t) - VELLUM_SIGNATURE_SIZE)

typedef char vellum_ticket_size_check[sizeof(vellum_ticket_t) == 120 ? 1 : -1];

/* Account id (low 32 bits of the SteamID) for a public key. 0/1 are LAN/PENDING. */
static inline authum_u32_t
vellum_account_id_from_key(const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    authum_u32_t id = (authum_u32_t)public_key[0] | ((authum_u32_t)public_key[1] << 8) |
                      ((authum_u32_t)public_key[2] << 16) | ((authum_u32_t)public_key[3] << 24);

    id &= 0x7FFFFFFFu;
    return id >= 2u ? id : id + 2u;
}

/* An old v1 ticket (pre-signature revloader). */
static inline int
vellum_ticket_is_v1(authum_cptr ticket, authum_usize_t ticket_len)
{
    if (authum_null_eq(ticket) || ticket_len != (authum_usize_t)VELLUM_TICKET_V1_SIZE)
    {
        return 0;
    }

    authum_u32_t magic;

    authum_memory_copy(&magic, ticket, sizeof magic);

    unsigned short version;

    authum_memory_copy(&version, (const authum_byte_t *)ticket + sizeof magic, sizeof version);

    return magic == VELLUM_TICKET_MAGIC && version == VELLUM_TICKET_V1_VERSION;
}

/* Any blob that claims to be Vellum (magic + size), well-formed or not. */
static inline int
vellum_ticket_is_vellum(authum_cptr ticket, authum_usize_t ticket_len)
{
    authum_u32_t magic;

    if (authum_null_eq(ticket) || ticket_len != (authum_usize_t)sizeof(vellum_ticket_t))
    {
        return 0;
    }
    authum_memory_copy(&magic, ticket, sizeof magic);
    return magic == VELLUM_TICKET_MAGIC;
}

/* Layout check only — the signature still has to be verified. */
static inline int
vellum_ticket_header_ok(const vellum_ticket_t *t)
{
    return t->magic == VELLUM_TICKET_MAGIC && t->version == VELLUM_TICKET_VERSION &&
           t->flags == 0 && t->reserved == 0;
}

/* Client side: everything but the signature, which is then made over
 * VELLUM_TICKET_SIGNED_SIZE bytes of `t`. */
static inline void
vellum_ticket_prepare(vellum_ticket_t *t, authum_u32_t server_ip, unsigned short server_port,
                      authum_u64_t timestamp,
                      const authum_byte_t public_key[VELLUM_PUBLIC_KEY_SIZE])
{
    authum_memory_set(t, 0, sizeof(*t));
    t->magic = VELLUM_TICKET_MAGIC;
    t->version = VELLUM_TICKET_VERSION;
    t->server_ip = server_ip;
    t->server_port = server_port;
    t->timestamp = timestamp;
    authum_memory_copy(t->public_key, public_key, VELLUM_PUBLIC_KEY_SIZE);
}

#endif /* QPROTO_VELLUM_TICKET_H */
