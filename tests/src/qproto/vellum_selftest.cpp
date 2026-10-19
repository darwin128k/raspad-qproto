#include "qproto/precompiled.h"
#include "qproto/qproto_authorizers.h"
#include "qproto/vellum_ticket.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

int main()
{
	int failures = 0;

	printf("sizeof(VellumTicket) = %zu (expect 64)\n", sizeof(VellumTicket));
	if (sizeof(VellumTicket) != 64) {
		printf("[FAIL] ticket size is not 64\n");
		failures++;
	}

	VellumTicket t = {};
	const char *ident = "TESTPC-DEADBEEF";
	if (!Vellum_FillTicket(&t, ident, strlen(ident))) {
		printf("[FAIL] Vellum_FillTicket rejected a valid ident\n");
		return 1;
	}

	authdata_t authdata = {};
	authdata.authTicket = (const uint8_t*)&t;
	authdata.ticketLen = sizeof(t);

	client_auth_kind kind = VellumAuthorize(&authdata);
	bool ok = kind == CA_VELLUM
		&& authdata.steamId == t.account_id
		&& authdata.authKeyLen == strlen(ident)
		&& memcmp(authdata.authKey, ident, strlen(ident)) == 0;
	printf("[%s] VellumAuthorize kind=%d steamId=%u ident=%s\n",
		ok ? "OK" : "FAIL", (int)kind, authdata.steamId, authdata.authKey);
	failures += !ok;

	VellumTicket junk = t;
	junk.checksum ^= 1;
	authdata_t bad = {};
	bad.authTicket = (const uint8_t*)&junk;
	bad.ticketLen = sizeof(junk);
	bool rejectOk = VellumAuthorize(&bad) == CA_UNKNOWN;
	printf("[%s] bad checksum rejected\n", rejectOk ? "OK" : "FAIL");
	failures += !rejectOk;

	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d FAILED\n", failures);
	return failures;
}
