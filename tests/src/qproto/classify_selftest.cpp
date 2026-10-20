// Sanity check for the non-ticket classifiers from classic HLDS auth client_auth.cpp /
// authorizer.cpp: Setti authorizer (fixed 0x300-byte ticket + magic constants),
// SXEI authorizer ("*HID" userinfo key), NoSteam47 authorizer/NoSteam48 authorizer
// (protocol-only catch-all). Also checks Qproto_Authorize_Client's dispatch order.
// (Classic plugins also have a CHLTVAuthorizer - deliberately not ported, see qproto_shared.h's
// comment on CA_HLTV's removal for why an HLTV connection can never reach this code.)
#include "qproto/qproto_authorizers.h"
#include "qproto/vellum_ticket.h"
#include <cstdio>
#include <cstring>

int main()
{
	int failures = 0;

	// 1) Setti: exact ticket length (0x300) + at least one of the 4 magic DWORDs.
	{
		uint32_t ticket[0x300 / 4] = {};
		ticket[1] = 0xC7DB6023; // SETTI_KEY2
		authdata_t authdata = {};
		authdata.authTicket = (const uint8_t*)ticket;
		authdata.ticketLen = sizeof(ticket);
		client_auth_kind kind = SettiAuthorize(&authdata);
		bool ok = kind == CA_SETTI && authdata.steamId == STEAM_ID_LAN;
		printf("[%s] SettiAuthorize recognizes ticket carrying SETTI_KEY2\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}
	{
		uint32_t ticket[0x300 / 4] = {}; // right length, no magic present
		authdata_t authdata = {};
		authdata.authTicket = (const uint8_t*)ticket;
		authdata.ticketLen = sizeof(ticket);
		bool ok = SettiAuthorize(&authdata) == CA_UNKNOWN;
		printf("[%s] SettiAuthorize rejects right-length ticket without magic\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}

	// 2) SXEI: hex hardware id from the engine-protected "*HID" userinfo key.
	{
		authdata_t authdata = {};
		authdata.sxeiHidHex = "1A2B3C4D";
		client_auth_kind kind = SXEIAuthorize(&authdata);
		bool ok = kind == CA_SXEI && authdata.steamId == (0x1A2B3C4Du << 1);
		printf("[%s] SXEIAuthorize decodes hex *HID (steamid=%u)\n", ok ? "OK" : "FAIL", authdata.steamId);
		if (!ok) failures++;
	}
	{
		authdata_t authdata = {};
		authdata.sxeiHidHex = "not-hex!";
		bool ok = SXEIAuthorize(&authdata) == CA_UNKNOWN;
		printf("[%s] SXEIAuthorize rejects unparseable *HID\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}

	// 3) NoSteam47/48: protocol-only, ticket content irrelevant.
	{
		authdata_t authdata = {};
		authdata.protocol = 47;
		bool ok = NoSteam47Authorize(&authdata) == CA_NO_STEAM_47 && NoSteam48Authorize(&authdata) == CA_UNKNOWN;
		printf("[%s] protocol=47 matches NoSteam47Authorize only\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}
	{
		authdata_t authdata = {};
		authdata.protocol = 48;
		bool ok = NoSteam48Authorize(&authdata) == CA_NO_STEAM_48 && NoSteam47Authorize(&authdata) == CA_UNKNOWN;
		printf("[%s] protocol=48 matches NoSteam48Authorize only\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}

	// 4) Dispatch order: a client with a valid *HID hint wins even if it also happens to
	//    carry a Setti-shaped ticket - SXEI is checked first, exactly like classic own
	//    authorizer registration order.
	{
		uint32_t ticket[0x300 / 4] = {};
		ticket[5] = 0xB4C43105; // SETTI_KEY4
		authdata_t authdata = {};
		authdata.authTicket = (const uint8_t*)ticket;
		authdata.ticketLen = sizeof(ticket);
		authdata.sxeiHidHex = "1A2B3C4D";
		authdata.protocol = 48;
		client_auth_kind kind = Qproto_Authorize_Client(&authdata, true, true);
		bool ok = kind == CA_SXEI;
		printf("[%s] Qproto_Authorize_Client prioritizes SXEI over Setti/NoSteam48 (got kind=%d)\n", ok ? "OK" : "FAIL", (int)kind);
		if (!ok) failures++;
	}

	// 5) Dispatch fallback: no ticket, no *HID hint, protocol=47 -> CA_NO_STEAM_47.
	{
		authdata_t authdata = {};
		authdata.protocol = 47;
		client_auth_kind kind = Qproto_Authorize_Client(&authdata, true, true);
		bool ok = kind == CA_NO_STEAM_47;
		printf("[%s] Qproto_Authorize_Client falls back to NoSteam47 with no ticket (got kind=%d)\n", ok ? "OK" : "FAIL", (int)kind);
		if (!ok) failures++;
	}

	// 6) Vellum ticket is recognized as CA_VELLUM, not a RevEmu-family kind.
	{
		VellumTicket t = {};
		const char *ident = "TESTPC-DEADBEEF";
		Vellum_FillTicket(&t, ident, strlen(ident));
		authdata_t authdata = {};
		authdata.authTicket = (const uint8_t*)&t;
		authdata.ticketLen = sizeof(t);
		authdata.protocol = 48;
		client_auth_kind kind = Qproto_Authorize_Client(&authdata, true, true);
		bool ok = kind == CA_VELLUM;
		printf("[%s] Qproto_Authorize_Client classifies Vellum ticket (got kind=%d)\n", ok ? "OK" : "FAIL", (int)kind);
		if (!ok) failures++;
	}

	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", failures);
	return failures;
}
