// Standalone sanity check for the ported Rijndael/SHA files: known test vectors only,
// no engine/qproto-specific logic. Not part of the plugin build.
#include "precompiled.h"
#include <cstdio>

static bool hexEq(const unsigned char* data, size_t len, const char* hex)
{
	char buf[256] = {};
	for (size_t i = 0; i < len; i++)
		snprintf(buf + i * 2, 3, "%02x", data[i]);
	return strcmp(buf, hex) == 0;
}

int main()
{
	int failures = 0;

	// FIPS-197 AES-128 ECB known-answer test.
	{
		unsigned char key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
		unsigned char pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		                         0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char ct[16] = {};

		CRijndael aes;
		aes.MakeKey((char const*)key, CRijndael::sm_chain0, 16, 16);
		aes.EncryptBlock((char const*)pt, (char*)ct);

		bool ok = hexEq(ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
		printf("[%s] AES-128 ECB known-answer test\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;

		unsigned char back[16] = {};
		aes.DecryptBlock((char const*)ct, (char*)back);
		bool okRound = memcmp(back, pt, 16) == 0;
		printf("[%s] AES-128 decrypt round-trip\n", okRound ? "OK" : "FAIL");
		if (!okRound) failures++;
	}

	// SHA-1("abc") known-answer test.
	{
		sha2 h;
		h.Init(sha2::enuSHA1);
		h.Update((const sha_byte*)"abc", 3);
		h.End();
		int len;
		const char* raw = h.RawHash(len);
		bool ok = len == 20 && hexEq((const unsigned char*)raw, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
		printf("[%s] SHA-1(\"abc\") known-answer test\n", ok ? "OK" : "FAIL");
		if (!ok) failures++;
	}

	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", failures);
	return failures;
}
