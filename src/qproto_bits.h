#pragma once

// Small bit-twiddling helpers used by the ported crypto (sha2.h/Rijndael) that in
// upstream classic come from osconf.h (rotl/rotr/rotr64) and HLSDK's mathlib.h (bswap).
// Neither has any engine dependency, so they're reproduced here verbatim instead of
// pulling in ReHLDS's full SDK header tree.

#include <cstdint>

inline uint32_t rotl(uint32_t x, int r)
{
	return (x << r) | (x >> (32 - r));
}

inline uint32_t rotr(uint32_t x, int r)
{
	return (x >> r) | (x << (32 - r));
}

inline uint64_t rotl64(uint64_t x, int r)
{
	return (x << r) | (x >> (64 - r));
}

inline uint64_t rotr64(uint64_t x, int r)
{
	return (x >> r) | (x << (64 - r));
}

template <typename T>
inline T bswap(T s)
{
	switch (sizeof(T))
	{
	case 2: { auto res = __builtin_bswap16(*(uint16_t *)&s); return *(T *)&res; }
	case 4: { auto res = __builtin_bswap32(*(uint32_t *)&s); return *(T *)&res; }
	case 8: { auto res = __builtin_bswap64(*(uint64_t *)&s); return *(T *)&res; }
	default: return s;
	}
}
