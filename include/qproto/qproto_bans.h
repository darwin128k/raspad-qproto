#pragma once

#include <cstdint>
#include <cstddef>

// Bans by raw auth key (HDD serial / volume id / sXe Injected hardware id) - the
// value qproto derives an emulated SteamID *from*, not the SteamID itself. A banned
// player who just reruns their ticket generator gets a new fake SteamID for free;
// the underlying HDD serial/volume id/hardware id does not change, so banning that
// is what actually sticks. authdata_t::authKeyKind/authKey/authKeyLen (populated by
// every authorizer in qproto_authorizers.cpp) exist specifically to make this possible.
//
// Loaded from qproto_bans.cfg (search: addons/qproto/ → gamedir → HLDS root; see
// qproto_paths.h): one hex-encoded key per line. qproto_hook.cpp logs the exact hex
// string for every successfully emulated auth, so running a client once and copying
// that line into qproto_bans.cfg is the intended workflow for banning them.

void Qproto_Bans_Load();
bool Qproto_Bans_IsBanned(const uint8_t* key, size_t len);

// Adds a key to the in-memory ban list AND appends its hex encoding to
// qproto_bans.cfg on disk, so it survives a server restart. Returns false if
// key/len is invalid (len==0 or too long), the table is full, or the key is
// already banned (no duplicate entries).
bool Qproto_Bans_Add(const uint8_t* key, size_t len);

// Removes a key from the in-memory ban list and rewrites qproto_bans.cfg from what
// remains (there's no clean way to delete one line from a text file in place).
// Returns false if the key wasn't banned.
bool Qproto_Bans_Remove(const uint8_t* key, size_t len);

// Exposed separately for unit testing (tests/src/qproto/bans_selftest.cpp) - pure
// parsing logic, no file I/O or engine dependency. Decodes one already-trimmed,
// comment-stripped line of hex digits into outKey (must be at least strlen(line)/2
// bytes); returns false (outLen untouched) if the line isn't valid even-length hex.
bool Qproto_Bans_ParseHexLine(const char* line, uint8_t* outKey, size_t* outLen);
