#pragma once

#include <cstdint>

// Minimal stand-in for Valve's CSteamID (steamclientpublic.h), which full Steam SDK headers pull in
// wholesale from the Steam SDK. We only need GetAccountID(), and per the real struct's
// layout (public/steam/steamclientpublic.h, union SteamID_t / SteamIDComponent_t on a
// little-endian target): a plain 64-bit value whose low 32 bits are the account ID.
// Ticket structs sent by RevEmu-family emulators embed this same 8-byte layout, so this
// must stay bit-compatible even though it doesn't pull in the rest of the Steam SDK.
struct MiniSteamID
{
	uint64_t bits;

	uint32_t GetAccountID() const
	{
		return (uint32_t)(bits & 0xFFFFFFFFu);
	}
};
