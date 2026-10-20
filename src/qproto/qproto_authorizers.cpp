#include "qproto/qproto_authorizers.h"
#include "qproto/qproto_utils.h"
#include "qproto/qproto_ministeamid.h"
#include "qproto/qproto_cfg.h"
#include "qproto/vellum_ticket.h"
#include "qproto/precompiled.h"
#include "host_crypto.h"
#include <cstring>
#include <cstdio>	// sscanf, SXEIAuthorize

// Ported from classic's classic_authorizers.cpp (GPLv3): the RevEmu-family ticket
// format and crypto is identical across dproto/classic/qproto (same community-derived
// wire format - confirmed independently this session by decompiling dproto's binary
// and finding the exact same Setti magic constants at the exact same ticket offsets).
// AES-ECB + SHA-256 go through Authum host (lh), not vendored Rijndael/sha2.

#define IDREVHEADER	(('r' << 16) + ('e' << 8) + 'v')	// little-endian "rev"

enum
{
	REVEMU_SIGNATURE = IDREVHEADER,
	REVEMU_SIGNATURE2 = 0
};

enum
{
	REVEMU_KEY_LEN = 32,
	REVEMU_BLOCK_SIZE = 32,
	REVEMU_SHA256_LEN = 32
};

static const char* g_RevEmuCryptKey = "_YOU_SERIOUSLY_NEED_TO_GET_LAID_";

uint32_t revHash(const char* str, int n)
{
	uint32_t hash = 0x4E67C6A7;

	for (int cc = *str; cc && n != 0; cc = *++str, --n) {
		hash ^= (hash >> 2) + cc + 32 * hash;
	}

	return hash;
}

static void RevEmuFinishAuthorization(authdata_t* authdata, const char* authStr, size_t authKeyMaxLen, bool stripSpecialChars)
{
	uint32_t volumeId;
	char hddsn[256];

	if (IsHddsnNumber(authStr)) {
		authdata->authKeyKind = AK_HDDSN;

		if (stripSpecialChars) {
			authdata->authKeyLen = strecpy(hddsn, authStr, authKeyMaxLen, " \\/-");
			authStr = hddsn;
		}
		else {
			size_t l = strlen(authStr);
			authdata->authKeyLen = l < authKeyMaxLen ? l : authKeyMaxLen;
		}
	}
	else {
		authdata->authKeyKind = AK_VOLUMEID;

		volumeId = strtoul(authStr, nullptr, 10) & 0x7FFFFFFF;
		authdata->authKeyLen = volumeId ? sizeof(volumeId) : 0; // can't be zero
		authStr = (char*)&volumeId;
	}

	if (authdata->authKeyLen) {
		memcpy(authdata->authKey, authStr, authdata->authKeyLen);
		authdata->authKey[authdata->authKeyLen] = '\0';

		authdata->steamId = revHash(authdata->authKey) << 1;
	}
	else {
		authdata->steamId = STEAM_ID_PENDING; // macro from qproto_shared.h
		authdata->authKeyKind = AK_OTHER;
	}
}

template <typename ticket_t>
static bool RevEmu2009to2013Authorize(const ticket_t* ticket, authdata_t* authdata, bool stripSpecialChars)
{
	enum { VERSION = 0x53 };

	if (ticket->Version != VERSION || ticket->RevSignature != REVEMU_SIGNATURE || ticket->Signature2 != REVEMU_SIGNATURE2)
		return false;

	char DecryptedAuthKey[REVEMU_KEY_LEN];
	if (!qproto_aes_ecb_decrypt_block(g_RevEmuCryptKey, REVEMU_KEY_LEN, ticket->EncryptedKey,
					  DecryptedAuthKey, REVEMU_BLOCK_SIZE))
		return false;

	char DecryptedAuthData[REVEMU_BLOCK_SIZE + 1];
	if (!qproto_aes_ecb_decrypt_block(DecryptedAuthKey, REVEMU_KEY_LEN, ticket->EncryptedData,
					  DecryptedAuthData, REVEMU_BLOCK_SIZE))
		return false;

	DecryptedAuthData[REVEMU_BLOCK_SIZE] = '\0';

	unsigned char digest[REVEMU_SHA256_LEN];
	if (!qproto_sha256(DecryptedAuthData, REVEMU_SHA256_LEN, digest))
		return false;
	if (memcmp(digest, ticket->Digest, REVEMU_SHA256_LEN) != 0)
		return false;

	uint32_t hash = revHash(DecryptedAuthData);
	uint32_t accid = ticket->SteamID.GetAccountID();

	if (hash != ticket->Hash || (uint32_t)(hash << 1) != accid)
		return false;

	RevEmuFinishAuthorization(authdata, DecryptedAuthData, sizeof DecryptedAuthData - 1, stripSpecialChars);
	return true;
}

struct RevEmu2013Ticket_t
{
	uint32_t	Version;
	uint32_t	Hash;
	uint32_t	RevSignature;
	uint32_t	Signature2;
	MiniSteamID	SteamID;
	uint32_t	ExpireTime;
	uint32_t	NotCreationTime;
	uint32_t	Unk20;
	uint32_t	Unk24;
	char		EncryptedData[REVEMU_BLOCK_SIZE];
	char		EncryptedKey[REVEMU_BLOCK_SIZE];
	char		Digest[REVEMU_SHA256_LEN];
};

struct SC2009Ticket_t
{
	uint32_t	Version;
	uint32_t	Hash;
	uint32_t	RevSignature;
	uint32_t	Signature2;
	MiniSteamID	SteamID;
	char		EncryptedData[REVEMU_BLOCK_SIZE];
	char		EncryptedKey[REVEMU_BLOCK_SIZE];
	char		Digest[REVEMU_SHA256_LEN];
};

struct RevTicket_t
{
	uint32_t	Version;
	uint32_t	Hash;
	uint32_t	RevSignature;
	uint32_t	Signature2;
	MiniSteamID	SteamID;
	char		TicketBuf[128];
};

client_auth_kind RevEmu2013Authorize(authdata_t* authdata)
{
	if (authdata->ticketLen < sizeof(RevEmu2013Ticket_t))
		return CA_UNKNOWN;

	// per classic: RevEmu2013/SC2009 always strip special chars from HDDSN-formatted keys
	return RevEmu2009to2013Authorize((const RevEmu2013Ticket_t*)authdata->authTicket, authdata, true) ? CA_REVEMU_2013 : CA_UNKNOWN;
}

client_auth_kind SteamClient2009Authorize(authdata_t* authdata)
{
	if (authdata->ticketLen < sizeof(SC2009Ticket_t))
		return CA_UNKNOWN;

	return RevEmu2009to2013Authorize((const SC2009Ticket_t*)authdata->authTicket, authdata, true) ? CA_STEAMCLIENT_2009 : CA_UNKNOWN;
}

client_auth_kind RevEmuAuthorize(authdata_t* authdata)
{
	enum { VERSION = 0x4A };

	if (authdata->ticketLen < sizeof(RevTicket_t))
		return CA_UNKNOWN;

	// Ticket is const, but we need to temporarily NUL a byte to hash the string safely -
	// same trick classic uses ("keep value for revert") to avoid needing a scratch copy.
	RevTicket_t* ticket = (RevTicket_t*)authdata->authTicket;
	if (ticket->Version != VERSION || ticket->RevSignature != REVEMU_SIGNATURE || ticket->Signature2 != REVEMU_SIGNATURE2)
		return CA_UNKNOWN;

	char saved = ticket->TicketBuf[sizeof(ticket->TicketBuf) - 1];
	ticket->TicketBuf[sizeof(ticket->TicketBuf) - 1] = '\0';

	uint32_t hash = revHash(ticket->TicketBuf);
	uint32_t accid = ticket->SteamID.GetAccountID();

	if (hash != ticket->Hash || (uint32_t)(hash << 1) != accid) {
		ticket->TicketBuf[sizeof(ticket->TicketBuf) - 1] = saved;
		return CA_UNKNOWN;
	}

	RevEmuFinishAuthorization(authdata, ticket->TicketBuf, sizeof(ticket->TicketBuf) - 1, false);
	return CA_REVEMU;
}

// Ported from MultiEmulator's Emulators/OldRevEmu.h GenerateOldRevEmu() (an open-source
// tool that generates test tickets specifically for dproto/classic servers, found this
// session - confirms our other formats byte-for-byte and gives us this one, which we
// hadn't seen documented anywhere else). No AES/SHA at all - just a magic + XOR.
#pragma pack(push, 1)
struct OldRevTicket_t
{
	uint32_t Header;      // must be 0xFFFF
	uint32_t SteamIdEnc;  // (steamId ^ 0xC9710266) << 1
	uint16_t Reserved;    // must be 0
};
#pragma pack(pop)

client_auth_kind OldRevEmuAuthorize(authdata_t* authdata)
{
	if (authdata->ticketLen != sizeof(OldRevTicket_t))
		return CA_UNKNOWN;

	const OldRevTicket_t* ticket = (const OldRevTicket_t*)authdata->authTicket;
	if (ticket->Header != 0xFFFF || ticket->Reserved != 0)
		return CA_UNKNOWN;

	// Inverse of the generator's (steamId ^ 0xC9710266) << 1. Note this is NOT
	// (encoded >> 1) ^ key: left-shift distributes over XOR, so encoded actually
	// equals (steamId << 1) ^ (key << 1), and undoing it means XOR-ing with the
	// *shifted* key before shifting back - order matters here.
	authdata->steamId = (ticket->SteamIdEnc ^ (0xC9710266u << 1)) >> 1;
	authdata->authKeyKind = AK_OTHER;
	authdata->authKeyLen = 0;

	return CA_OLD_REVEMU;
}

// Ported verbatim from classic's CSettiAuthorizer::authorize - exact ticket length and
// magic constants (credited there to "vityan666"). Setti is a monitoring/promotion
// bot, not an attacker - it must be recognized and let through, not silently dropped
// into a generic reject bucket.
client_auth_kind SettiAuthorize(authdata_t* authdata)
{
	enum {
		TICKET_LEN = 0x300,
		SETTI_KEY1 = 0xD4CA7F7B,
		SETTI_KEY2 = 0xC7DB6023,
		SETTI_KEY3 = 0x6D6A2E1F,
		SETTI_KEY4 = 0xB4C43105,
	};

	if (authdata->ticketLen != TICKET_LEN)
		return CA_UNKNOWN;

	const uint32_t* ikey = (const uint32_t*)authdata->authTicket;
	if (!(ikey[0] == SETTI_KEY1 || ikey[1] == SETTI_KEY2 || ikey[2] == SETTI_KEY3 || ikey[5] == SETTI_KEY4))
		return CA_UNKNOWN;

	authdata->steamId = STEAM_ID_LAN;
	authdata->authKeyKind = AK_OTHER;
	authdata->authKeyLen = 0;
	return CA_SETTI;
}

// Ported from classic's CNoSteam47Authorizer/CNoSteam48Authorizer - the catch-all for
// "native Steam auth failed and no ticket format above matched", split by protocol
// version exactly like dproto.cfg's separate cid_NoSteam47/cid_NoSteam48. Deliberately
// does NOT look at ticket bytes at all (mirrors classic exactly) - garbage/unrecognized
// ticket content is treated the same as no ticket, protocol is the only signal.
client_auth_kind NoSteam47Authorize(authdata_t* authdata)
{
	if (authdata->protocol != 47)
		return CA_UNKNOWN;

	authdata->steamId = STEAM_ID_LAN;
	authdata->authKeyKind = AK_OTHER;
	authdata->authKeyLen = 0;
	return CA_NO_STEAM_47;
}

client_auth_kind NoSteam48Authorize(authdata_t* authdata)
{
	if (authdata->protocol != 48)
		return CA_UNKNOWN;

	authdata->steamId = STEAM_ID_LAN;
	authdata->authKeyKind = AK_OTHER;
	authdata->authKeyLen = 0;
	return CA_NO_STEAM_48;
}

// Ported from classic's CSXEIAuthorizer::authorize - trusts the engine-protected "*HID"
// userinfo key (pre-extracted by the caller, see authdata_t.sxeiHidHex) as a hex hardware
// id from the sXe Injected anti-cheat. No ticket bytes involved at all.
client_auth_kind SXEIAuthorize(authdata_t* authdata)
{
	if (!g_qproto_config.enableSXEI)
		return CA_UNKNOWN;

	if (!authdata->sxeiHidHex || !authdata->sxeiHidHex[0])
		return CA_UNKNOWN;

	uint32_t sxeId;
	if (sscanf(authdata->sxeiHidHex, "%X", &sxeId) != 1)
		return CA_UNKNOWN;

	if (sxeId == 0) {
		authdata->steamId = STEAM_ID_PENDING;
		authdata->authKeyKind = AK_OTHER;
		authdata->authKeyLen = 0;
	}
	else {
		authdata->steamId = sxeId << 1;
		authdata->authKeyKind = AK_SXEID;
		authdata->authKeyLen = sizeof(uint32_t);
		memcpy(authdata->authKey, &sxeId, sizeof(sxeId));
	}

	return CA_SXEI;
}

client_auth_kind VellumAuthorize(authdata_t* authdata)
{
	if (authdata->ticketLen != sizeof(VellumTicket))
		return CA_UNKNOWN;

	const VellumTicket* ticket = (const VellumTicket*)authdata->authTicket;
	if (!Vellum_TicketValid(ticket, authdata->ticketLen))
		return CA_UNKNOWN;

	authdata->steamId = ticket->account_id;
	authdata->authKeyKind = AK_OTHER;
	authdata->authKeyLen = ticket->ident_len;
	if (authdata->authKeyLen > MAX_AUTHKEY_LEN)
		authdata->authKeyLen = MAX_AUTHKEY_LEN;
	memcpy(authdata->authKey, ticket->ident, authdata->authKeyLen);
	authdata->authKey[authdata->authKeyLen] = '\0';
	return CA_VELLUM;
}

client_auth_kind qproto_authorize_client(authdata_t* authdata, bool /*sc2009RevCompat*/, bool /*forceAuthVersion2018Plus*/)
{
	client_auth_kind r;

	// Order matches classic's own authorizer registration order (classic_authorizers.cpp
	// classic_Init_Authorizers): userinfo-based checks first, then ticket formats from
	// most to least specific, with the protocol-only catch-alls tried last. (classic's
	// CHLTVAuthorizer isn't ported - see qproto_shared.h's comment on CA_HLTV's removal.)
	if ((r = SXEIAuthorize(authdata)) != CA_UNKNOWN) return r;
	if ((r = SettiAuthorize(authdata)) != CA_UNKNOWN) return r;

	if (g_qproto_config.enableVellum && (r = VellumAuthorize(authdata)) != CA_UNKNOWN) return r;
	if (g_qproto_config.enableRevEmu && (r = RevEmuAuthorize(authdata)) != CA_UNKNOWN) return r;
	if (g_qproto_config.enableRevEmu2013 && (r = RevEmu2013Authorize(authdata)) != CA_UNKNOWN) return r;
	if (g_qproto_config.enableSC2009 && (r = SteamClient2009Authorize(authdata)) != CA_UNKNOWN) return r;
	if (g_qproto_config.enableOldRevEmu && (r = OldRevEmuAuthorize(authdata)) != CA_UNKNOWN) return r;

	if ((r = NoSteam47Authorize(authdata)) != CA_UNKNOWN) return r;
	if ((r = NoSteam48Authorize(authdata)) != CA_UNKNOWN) return r;

	return CA_UNKNOWN;
}
