#include "qproto_utils.h"
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <climits>

// Ported from classic's classic_utils.cpp (GPLv3), verbatim logic.

size_t strecpy(char* dest, const char* src, size_t maxlen, const char* exceptChars, char repChar)
{
	size_t len = 0;

	for (; *src && len < maxlen; src++) {
		char c = *src;
		if (strchr(exceptChars, c)) {
			if (!repChar)
				continue;

			c = repChar;
		}

		len++;
		*dest++ = c;
	}

	*dest = '\0';
	return len;
}

bool IsValidId(uint32_t authId)
{
	const uint32_t STEAM_ID_PENDING = 1;
	return authId > STEAM_ID_PENDING;
}

bool IsHddsnNumber(const char* authstring)
{
	for (const char* c = authstring; *c; c++) {
		// HDDSNs have spaces or letters
		if (*c < '0' || *c > '9')
			return true;
	}

	return strtoull(authstring, nullptr, 10) >= UINT32_MAX; // SSD
}

// See classic's comment: some NVMe SSDs report this fixed bogus serial via a
// Windows API quirk (Storage Descriptor path instead of the real driver call);
// treat it as invalid rather than minting a colliding SteamID from it.
static const char* BadHddsnNumber = "0000_0000_0000_0000_0000_0100_0";

bool IsValidHddsnNumber(const void* data, size_t maxlen)
{
	size_t n = strlen(BadHddsnNumber);
	if (maxlen < n) n = maxlen;
	return memcmp(data, BadHddsnNumber, n) != 0;
}
