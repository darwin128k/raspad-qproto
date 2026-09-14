// Sanity check for the non-ticket classifiers ported from classic's client_auth.cpp /
// classic_authorizers.cpp: CHLTVAuthorizer ("*hltv" userinfo key), CSettiAuthorizer
// (fixed 0x300-byte ticket + magic constants), CNoSteam47Authorizer/CNoSteam48Authorizer
// (protocol-only catch-all). Also checks Qproto_Authorize_Client's dispatch order -
// HLTV/Setti must win over the RevEmu-family authorizers and the NoSteam47/48 fallback.
#include "qproto/qproto_authorizers.h"
#include <cstdio>
#include <cstring>

int main()
{
	int failures = 0;

	// 1) HLTV: recognized purely from hltvHint, regardless of ticket content.
	{
		authdata_t authdata = {};
		authdata.hltvHint = "1";
		client_auth_kind kind = HLTVAuthorize(&authdata);
		bool ok = kind == CA_HLTV && authdata.steamId == STEAM_ID_LAN;
		printf("[%s] HLTVAuthorize recognizes non-empty *hltv hint\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}
	{
		authdata_t authdata = {};
		authdata.hltvHint = "";
		bool ok = HLTVAuthorize(&authdata) == CA_UNKNOWN;
		printf("[%s] HLTVAuthorize rejects empty *hltv hint\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}

	// 2) Setti: exact ticket length (0x300) + at least one of the 4 magic DWORDs.
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

	// 4) Dispatch order: a client with *hltv set wins even if it also happens to carry
	//    a Setti-shaped ticket - HLTV is checked first, exactly like classic's own
	//    authorizer registration order.
	{
		uint32_t ticket[0x300 / 4] = {};
		ticket[5] = 0xB4C43105; // SETTI_KEY4
		authdata_t authdata = {};
		authdata.authTicket = (const uint8_t*)ticket;
		authdata.ticketLen = sizeof(ticket);
		authdata.hltvHint = "1";
		authdata.protocol = 48;
		client_auth_kind kind = Qproto_Authorize_Client(&authdata, true, true);
		bool ok = kind == CA_HLTV;
		printf("[%s] Qproto_Authorize_Client prioritizes HLTV over Setti/NoSteam48 (got kind=%d)\n", ok ? "OK" : "FAIL", (int)kind);
		if (!ok) failures++;
	}

	// 5) Dispatch fallback: no ticket, no hltv hint, protocol=47 -> CA_NO_STEAM_47.
	{
		authdata_t authdata = {};
		authdata.protocol = 47;
		client_auth_kind kind = Qproto_Authorize_Client(&authdata, true, true);
		bool ok = kind == CA_NO_STEAM_47;
		printf("[%s] Qproto_Authorize_Client falls back to NoSteam47 with no ticket (got kind=%d)\n", ok ? "OK" : "FAIL", (int)kind);
		if (!ok) failures++;
	}

	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", failures);
	return failures;
}
