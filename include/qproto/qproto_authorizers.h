#ifndef QPROTO_AUTHORIZERS_H
#define QPROTO_AUTHORIZERS_H

#include <stdint.h>
#include <stddef.h>
#include "qproto/qproto_shared.h"

/*
 * Taken from classic HLDS auth: authorizer sources (GPLv3), trimmed to the v1 scope
 * (Steam + RevEmu family: RevEmu >=9.74, RevEmu2013, SC2009). No engine dependency -
 * everything here works on raw bytes handed in by the caller.
 */

typedef struct authdata {
	/* in */
	const uint8_t *auth_ticket;
	size_t ticket_len;

	/*
	 * Context needed by the non-ticket authorizers below (HLTV/NoSteam47/NoSteam48),
	 * from classic HLDS authdata_t. Pre-extracted by the caller (qproto_hook.c, which
	 * has engine function pointers) rather than looked up in here, so this file stays
	 * engine-free and unit-testable in isolation.
	 */
	int protocol;			/* negotiated client protocol (47 or 48), from Info_ValueForKey(protinfo, "prot") */
	const char *sxei_hid_hex;	/* Info_ValueForKey(userinfo, "*HID"), or null/empty if absent */

	/* out */
	int idtype;			/* engine WONAuthIdType-style value (AUTH_IDTYPE_LOCAL etc.) */
	uint32_t steam_id;

	enum auth_key_kind auth_key_kind;
	size_t auth_key_len;
	char auth_key[MAX_AUTHKEY_LEN + 1];
} authdata_t;

/* authorize() returns CA_UNKNOWN if the ticket doesn't match this authorizer's format. */
enum client_auth_kind revemu_authorize(authdata_t *authdata);
enum client_auth_kind revemu_2013_authorize(authdata_t *authdata);
enum client_auth_kind steamclient_2009_authorize(authdata_t *authdata);
enum client_auth_kind old_revemu_authorize(authdata_t *authdata);

/*
 * Taken from classic HLDS auth: Setti/NoSteam47/NoSteam48 authorizers - none of these
 * parse an encrypted ticket, they just classify the connection context.
 */
enum client_auth_kind setti_authorize(authdata_t *authdata);
enum client_auth_kind nosteam47_authorize(authdata_t *authdata);
enum client_auth_kind nosteam48_authorize(authdata_t *authdata);

/*
 * Taken from classic HLDS auth: SXEI authorizer - identifies a client running the sXe
 * Injected anti-cheat by its hardware id, carried in the engine-protected "*HID"
 * userinfo key. Config-gated (EnableSXEI).
 */
enum client_auth_kind sxei_authorize(authdata_t *authdata);
enum client_auth_kind vellum_authorize(authdata_t *authdata);

/*
 * Tries all authorizers in turn (Vellum first among tickets, then RevEmu family);
 * returns CA_UNKNOWN if none match.
 * sc2009_rev_compat / force_auth_version_2018_plus mirror dproto.cfg's
 * SC2009_RevCompatMode and gate a stricter special-char-stripping mode.
 */
enum client_auth_kind qproto_authorize_client(authdata_t *authdata, int sc2009_rev_compat, int force_auth_version_2018_plus);

uint32_t rev_hash(const char *str, int n);

#endif /* QPROTO_AUTHORIZERS_H */
