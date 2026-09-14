// End-to-end sanity check for the ported RevEmu-family authorizer: build a synthetic
// ticket the way a real RevEmu2013 client would (encrypt with the fixed well-known key,
// then encrypt the payload with the per-session key, SHA-256 digest of the plaintext),
// feed it through our ported RevEmu2013Authorize(), and check it recovers the same
// SteamID/auth key. This exercises Rijndael+SHA256+revHash together, not just in
// isolation - the thing that actually matters for real client tickets.
#include "precompiled.h"
#include "qproto_authorizers.h"
#include <cstdio>
#include <cstring>

static const char* g_RevEmuCryptKey = "_YOU_SERIOUSLY_NEED_TO_GET_LAID_";

#define IDREVHEADER	(('r' << 16) + ('e' << 8) + 'v')

struct RevEmu2013Ticket_t
{
	uint32_t	Version;
	uint32_t	Hash;
	uint32_t	RevSignature;
	uint32_t	Signature2;
	uint64_t	SteamID;
	uint32_t	ExpireTime;
	uint32_t	NotCreationTime;
	uint32_t	Unk20;
	uint32_t	Unk24;
	char		EncryptedData[32];
	char		EncryptedKey[32];
	char		Digest[32];
};

int main()
{
	int failures = 0;

	// 1) Build the plaintext 32-byte auth-key block a real client would embed
	//    (an alphanumeric HDD serial, NUL-padded to fill the block). Deliberately not
	//    pure-digits: RevEmuFinishAuthorization treats a pure number that fits in
	//    uint32 as a "VolumeID" and reinterprets it as 4 raw binary bytes instead of
	//    keeping the string (see qproto_authorizers.cpp) - a real HDDSN-shaped string
	//    exercises the more common real-client code path.
	char plain[32] = {};
	strcpy(plain, "WDWCC4N2799381");

	uint32_t hash = revHash(plain);
	uint32_t accid = (uint32_t)(hash << 1);

	// 2) Per-session random key + SHA-256 digest of the plaintext block.
	char sessionKey[32];
	for (int i = 0; i < 32; i++) sessionKey[i] = (char)(0x11 * (i + 1));

	sha2 hSha;
	hSha.Init(sha2::enuSHA256);
	hSha.Update((const sha_byte*)plain, 32);
	hSha.End();
	int shaLen;
	const char* digest = hSha.RawHash(shaLen);

	// 3) Encrypt: EncryptedData = AES256(plain, sessionKey), EncryptedKey = AES256(sessionKey, fixedKey).
	RevEmu2013Ticket_t ticket = {};
	ticket.Version = 0x53;
	ticket.Hash = hash;
	ticket.RevSignature = IDREVHEADER;
	ticket.Signature2 = 0;
	ticket.SteamID = accid; // low 32 bits = account id, matches MiniSteamID layout

	CRijndael encData;
	encData.MakeKey(sessionKey, CRijndael::sm_chain0, 32, 32);
	encData.EncryptBlock(plain, ticket.EncryptedData);

	CRijndael encKey;
	encKey.MakeKey(g_RevEmuCryptKey, CRijndael::sm_chain0, 32, 32);
	encKey.EncryptBlock(sessionKey, ticket.EncryptedKey);

	memcpy(ticket.Digest, digest, 32);

	// 4) Feed it through the ported authorizer exactly as a connectionless-packet hook would.
	authdata_t authdata = {};
	authdata.authTicket = (const uint8_t*)&ticket;
	authdata.ticketLen = sizeof(ticket);

	client_auth_kind kind = RevEmu2013Authorize(&authdata);

	bool okKind = kind == CA_REVEMU_2013;
	printf("[%s] RevEmu2013Authorize recognized ticket (kind=%d)\n", okKind ? "OK" : "FAIL", (int)kind);
	if (!okKind) failures++;

	bool okId = authdata.steamId == accid;
	printf("[%s] recovered SteamID matches (%u vs expected %u)\n", okId ? "OK" : "FAIL", authdata.steamId, accid);
	if (!okId) failures++;

	bool okKey = authdata.authKeyLen == strlen(plain) && memcmp(authdata.authKey, plain, authdata.authKeyLen) == 0;
	printf("[%s] recovered auth key matches ('%s' vs expected '%s')\n", okKey ? "OK" : "FAIL", authdata.authKey, plain);
	if (!okKey) failures++;

	// 5) Negative test: garbage ticket must not be recognized.
	authdata_t garbage = {};
	unsigned char junk[sizeof(RevEmu2013Ticket_t)] = {};
	for (size_t i = 0; i < sizeof(junk); i++) junk[i] = (unsigned char)(i * 37);
	garbage.authTicket = junk;
	garbage.ticketLen = sizeof(junk);
	client_auth_kind garbageKind = RevEmu2013Authorize(&garbage);
	bool okReject = garbageKind == CA_UNKNOWN;
	printf("[%s] random garbage correctly rejected\n", okReject ? "OK" : "FAIL");
	if (!okReject) failures++;

	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", failures);
	return failures;
}
