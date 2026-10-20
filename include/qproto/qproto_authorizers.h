#pragma once

#include <cstdint>
#include <cstddef>
#include "qproto/qproto_shared.h"

// Taken from classic HLDS auth: authorizer sources (GPLv3), trimmed to the v1 scope
// (Steam + RevEmu family: RevEmu >=9.74, RevEmu2013, SC2009). No engine dependency -
// everything here works on raw bytes handed in by the caller.

struct authdata_t
{
	// in
	const uint8_t*	authTicket;
	size_t			ticketLen;

	// Context needed by the non-ticket authorizers below (HLTV/NoSteam47/NoSteam48),
	// from classic HLDS authdata_t. Pre-extracted by
	// the caller (qproto_hook.cpp, which has engine function pointers) rather than
	// looked up in here, so this file stays engine-free and unit-testable in isolation
	// (see qproto_authorizers's own test in tests/, which links none of extdll.h).
	int				protocol = 0;			// negotiated client protocol (47 or 48), from Info_ValueForKey(protinfo, "prot")
	const char*		sxeiHidHex = nullptr;	// Info_ValueForKey(userinfo, "*HID"), or null/empty if absent (sXe Injected hardware id, hex string)

	// out
	int				idtype;			// engine WONAuthIdType-style value (AUTH_IDTYPE_LOCAL etc.), wired up when this is plugged into the real connectionless hook
	uint32_t		steamId;

	auth_key_kind	authKeyKind;
	size_t			authKeyLen;
	char			authKey[MAX_AUTHKEY_LEN + 1];
};

// authorize() returns CA_UNKNOWN if the ticket doesn't match this authorizer's format.
client_auth_kind RevEmuAuthorize(authdata_t* authdata);
client_auth_kind RevEmu2013Authorize(authdata_t* authdata);
client_auth_kind SteamClient2009Authorize(authdata_t* authdata);
client_auth_kind OldRevEmuAuthorize(authdata_t* authdata);

// Taken from classic HLDS auth: Setti authorizer/NoSteam47 authorizer/NoSteam48 authorizer
// (authorizer.cpp) - none of these parse an encrypted ticket, they just
// classify the connection context (see field comments above). Classic plugins also have a
// CHLTVAuthorizer, deliberately not ported here - see the comment on CA_HLTV's
// removal in qproto_shared.h for why an HLTV proxy connection can never even reach
// this code on stock HLDS.
client_auth_kind SettiAuthorize(authdata_t* authdata);
client_auth_kind NoSteam47Authorize(authdata_t* authdata);
client_auth_kind NoSteam48Authorize(authdata_t* authdata);

// Taken from classic HLDS auth: SXEI authorizer - identifies a client running the sXe
// Injected anti-cheat by its hardware id, carried in the engine-protected "*HID"
// userinfo key (same trust level as "*hltv" - ordinary client code can't set keys
// starting with '*' via a plain setinfo). Config-gated (EnableSXEI).
client_auth_kind SXEIAuthorize(authdata_t* authdata);
client_auth_kind VellumAuthorize(authdata_t* authdata);

// Tries all authorizers in turn (Vellum first among tickets, then RevEmu family);
// returns CA_UNKNOWN if none match.
// sc2009RevCompat / forceAuthVersion2018Plus mirror dproto.cfg's SC2009_RevCompatMode and
// gate a stricter special-char-stripping mode classic plugins added in its 2018 wire revision.
client_auth_kind qproto_authorize_client(authdata_t* authdata, bool sc2009RevCompat, bool forceAuthVersion2018Plus);

uint32_t revHash(const char* str, int n = -1);
