#ifndef QPROTO_AUTHORIZERS_H
#define QPROTO_AUTHORIZERS_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

#include <qproto/shared.h>

/*
 * Classic HLDS auth authorizers (GPLv3), trimmed: Steam + RevEmu family.
 * Engine-free — works on raw bytes from the caller.
 */

struct qproto_authdata
{
    /* in */
    const authum_byte_t *auth_ticket;
    authum_usize_t ticket_len;

    /*
     * Context for non-ticket authorizers (NoSteam47/48, SXEI), pre-extracted
     * by hook.c so this file stays engine-free.
     */
    authum_i32_t protocol;             /* 47 or 48, from Info_ValueForKey(protinfo, "prot") */
    const authum_char_t *sxei_hid_hex; /* "*HID", or null/empty if absent */

    /*
     * Vellum context: where this server listens and what time it is. A signed
     * ticket must name one of server_ips (skipped when the count is 0) and
     * server_port (skipped when 0); now == 0 skips the clock check.
     */
    const authum_u32_t *server_ips; /* 1.2.3.4 -> 0x01020304 */
    authum_usize_t server_ip_count;
    authum_u32_t server_port;
    authum_i64_t now; /* UTC seconds */

    /* out */
    authum_i32_t idtype; /* engine AUTH_IDTYPE_* */
    authum_u32_t steam_id;

    qproto_auth_key_kind_t auth_key_kind;
    authum_usize_t auth_key_len;
    authum_char_t auth_key[QPROTO_MAX_AUTHKEY_LEN + 1];

    /*
     * Set when a ticket was recognised but must not get in (old Vellum v1,
     * bad signature, wrong server, key mismatch …). qproto_authorize_client
     * then stops — no protocol-only catch-all may take the client instead.
     */
    authum_bool_t rejected;
    authum_char_t reject_reason[128];
};
typedef struct qproto_authdata qproto_authdata_t;

/* Returns qproto_client_auth_kind_unknown if the ticket doesn't match. */
qproto_client_auth_kind_t
qproto_revemu_authorize(qproto_authdata_t *authdata);
qproto_client_auth_kind_t
qproto_revemu_2013_authorize(qproto_authdata_t *authdata);
qproto_client_auth_kind_t
qproto_steamclient_2009_authorize(qproto_authdata_t *authdata);
qproto_client_auth_kind_t
qproto_old_revemu_authorize(qproto_authdata_t *authdata);

qproto_client_auth_kind_t
qproto_setti_authorize(qproto_authdata_t *authdata);
qproto_client_auth_kind_t
qproto_nosteam47_authorize(qproto_authdata_t *authdata);
qproto_client_auth_kind_t
qproto_nosteam48_authorize(qproto_authdata_t *authdata);

qproto_client_auth_kind_t
qproto_sxei_authorize(qproto_authdata_t *authdata);
qproto_client_auth_kind_t
qproto_vellum_authorize(qproto_authdata_t *authdata);

qproto_client_auth_kind_t
qproto_authorize_client(qproto_authdata_t *authdata, authum_bool_t sc2009_rev_compat,
                        authum_bool_t force_auth_version_2018_plus);

authum_u32_t
qproto_rev_hash(const authum_char_t *str, authum_i32_t n);

#endif /* QPROTO_AUTHORIZERS_H */
