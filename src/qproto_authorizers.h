#pragma once

#include <cstdint>
#include <cstddef>
#include "classic_shared.h"

// Ported from classic's classic_authorizers.{h,cpp} (GPLv3), trimmed to the v1 scope
// (Steam + RevEmu family: RevEmu >=9.74, RevEmu2013, SC2009). No engine dependency -
// everything here works on raw bytes handed in by the caller.

struct authdata_t
{
	// in
	const uint8_t*	authTicket;
	size_t			ticketLen;

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

// Tries all v1 authorizers in turn (RevEmu family only); returns CA_UNKNOWN if none match.
// sc2009RevCompat / forceAuthVersion2018Plus mirror dproto.cfg's SC2009_RevCompatMode and
// gate a stricter special-char-stripping mode classic added in its 2018 wire revision.
client_auth_kind Qproto_Authorize_Client(authdata_t* authdata, bool sc2009RevCompat, bool forceAuthVersion2018Plus);

uint32_t revHash(const char* str, int n = -1);
