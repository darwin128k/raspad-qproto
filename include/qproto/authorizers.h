#ifndef QPROTO_AUTHORIZERS_H
#define QPROTO_AUTHORIZERS_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

#include "qproto/shared.h"

/*
 * Classic HLDS auth authorizers (GPLv3), trimmed: Steam + RevEmu family.
 * Engine-free — works on raw bytes from the caller.
 */

struct authdata
{
	/* in */
	const authum_byte_t *auth_ticket;
	authum_usize_t ticket_len;

	/*
	 * Context for non-ticket authorizers (NoSteam47/48, SXEI), pre-extracted
	 * by hook.c so this file stays engine-free.
	 */
	authum_i32_t protocol; /* 47 or 48, from Info_ValueForKey(protinfo, "prot") */
	const authum_char_t *sxei_hid_hex; /* "*HID", or null/empty if absent */

	/* out */
	authum_i32_t idtype; /* engine AUTH_IDTYPE_* */
	authum_u32_t steam_id;

	qproto_auth_key_kind_t auth_key_kind;
	authum_usize_t auth_key_len;
	authum_char_t auth_key[QPROTO_MAX_AUTHKEY_LEN + 1];
};
typedef struct authdata authdata_t;

/* authorize() returns qproto_client_auth_kind_unknown if the ticket doesn't match. */
qproto_client_auth_kind_t revemu_authorize(authdata_t *authdata);
qproto_client_auth_kind_t revemu_2013_authorize(authdata_t *authdata);
qproto_client_auth_kind_t steamclient_2009_authorize(authdata_t *authdata);
qproto_client_auth_kind_t old_revemu_authorize(authdata_t *authdata);

qproto_client_auth_kind_t setti_authorize(authdata_t *authdata);
qproto_client_auth_kind_t nosteam47_authorize(authdata_t *authdata);
qproto_client_auth_kind_t nosteam48_authorize(authdata_t *authdata);

qproto_client_auth_kind_t sxei_authorize(authdata_t *authdata);
qproto_client_auth_kind_t vellum_authorize(authdata_t *authdata);

qproto_client_auth_kind_t qproto_authorize_client(authdata_t *authdata, authum_bool_t sc2009_rev_compat,
					   authum_bool_t force_auth_version_2018_plus);

authum_u32_t rev_hash(const authum_char_t *str, authum_i32_t n);

#endif /* QPROTO_AUTHORIZERS_H */
