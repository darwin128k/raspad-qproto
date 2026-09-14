// Sanity check for Qproto_Bans_ParseHexLine - the one piece of the ban list (qproto_bans.h)
// that's pure logic with no engine dependency (Load/Add/Remove/IsBanned all need
// g_engfuncs.pfnGetGameDir and are exercised for real once deployed instead).
#include "qproto/qproto_bans.h"
#include <cstdio>
#include <cstring>

int main()
{
	int failures = 0;

	// 1) A valid even-length hex string decodes to the exact bytes.
	{
		uint8_t key[64];
		size_t len = 0;
		bool ok = Qproto_Bans_ParseHexLine("5744574334", key, &len);
		uint8_t expected[] = {0x57, 0x44, 0x57, 0x43, 0x34};
		bool matches = ok && len == sizeof(expected) && memcmp(key, expected, len) == 0;
		printf("[%s] valid hex line decodes correctly (len=%zu)\n", matches ? "OK" : "FAIL", len);
		if (!matches) failures++;
	}

	// 2) Mixed-case hex is accepted.
	{
		uint8_t key[64];
		size_t len = 0;
		bool ok = Qproto_Bans_ParseHexLine("1A2b3C4d", key, &len);
		uint8_t expected[] = {0x1A, 0x2B, 0x3C, 0x4D};
		bool matches = ok && len == sizeof(expected) && memcmp(key, expected, len) == 0;
		printf("[%s] mixed-case hex decodes correctly\n", matches ? "OK" : "FAIL");
		if (!matches) failures++;
	}

	// 3) Odd-length hex is rejected.
	{
		uint8_t key[64];
		size_t len = 0;
		bool ok = Qproto_Bans_ParseHexLine("abc", key, &len);
		printf("[%s] odd-length hex rejected\n", !ok ? "OK" : "FAIL");
		if (ok) failures++;
	}

	// 4) Non-hex characters are rejected.
	{
		uint8_t key[64];
		size_t len = 0;
		bool ok = Qproto_Bans_ParseHexLine("12gh", key, &len);
		printf("[%s] non-hex characters rejected\n", !ok ? "OK" : "FAIL");
		if (ok) failures++;
	}

	// 5) Empty line is rejected.
	{
		uint8_t key[64];
		size_t len = 0;
		bool ok = Qproto_Bans_ParseHexLine("", key, &len);
		printf("[%s] empty line rejected\n", !ok ? "OK" : "FAIL");
		if (ok) failures++;
	}

	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", failures);
	return failures;
}
