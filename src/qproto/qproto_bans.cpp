#include <cmath>	// must precede extdll.h - see qproto_hook.cpp for why
#include <extdll.h>
#include <enginecallback.h>
#include "qproto/qproto_bans.h"
#include "qproto/qproto_log.h"
#include "qproto/qproto_paths.h"
#include "qproto/qproto_shared.h"	// MAX_AUTHKEY_LEN

#include <cstdio>
#include <cstring>

namespace {

const int kMaxBans = 512;

struct BanEntry
{
	uint8_t key[MAX_AUTHKEY_LEN];
	size_t len;
};

BanEntry g_bans[kMaxBans];
int g_numBans;
char g_path[512]; // set by Qproto_Bans_Load(); empty until then

int HexVal(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

void HexEncode(const uint8_t* data, size_t len, char* out)
{
	for (size_t i = 0; i < len; i++) {
		snprintf(out + i * 2, 3, "%02x", data[i]);
	}
	out[len * 2] = '\0';
}

char* SkipSpaces(char* s)
{
	while (*s == ' ' || *s == '\t') s++;
	return s;
}

void RTrim(char* s)
{
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
		s[--n] = '\0';
	}
}

int FindBan(const uint8_t* key, size_t len)
{
	for (int i = 0; i < g_numBans; i++) {
		if (g_bans[i].len == len && memcmp(g_bans[i].key, key, len) == 0) return i;
	}
	return -1;
}

// Rewrites qproto_bans.cfg from scratch with the current in-memory list - used after
// Qproto_Bans_Remove, since there's no clean way to delete one line from a text file
// in place. Any hand-written comments in the file are lost on the next removal; adds
// (Qproto_Bans_Add) only ever append, so they don't have this problem.
void RewriteFile()
{
	if (!g_path[0]) return;

	FILE* f = fopen(g_path, "w");
	if (!f) {
		Qproto_Log("qproto_bans.cfg: failed to rewrite %s - bans kept in memory only until next restart", g_path);
		return;
	}

	fprintf(f, "# Raw auth key bans (HDD serial / volume id / sXe hardware id), one hex-encoded\n");
	fprintf(f, "# key per line. Rewritten automatically by qproto (qproto_ban_authkey/qproto_unban_authkey,\n");
	fprintf(f, "# see qproto_api.h) - hand edits survive until the next ban/unban triggers another rewrite.\n");
	for (int i = 0; i < g_numBans; i++) {
		char hex[MAX_AUTHKEY_LEN * 2 + 1];
		HexEncode(g_bans[i].key, g_bans[i].len, hex);
		fprintf(f, "%s\n", hex);
	}
	fclose(f);
}

} // namespace

bool Qproto_Bans_ParseHexLine(const char* line, uint8_t* outKey, size_t* outLen)
{
	size_t hexLen = strlen(line);
	if (hexLen == 0 || hexLen % 2 != 0 || hexLen / 2 > MAX_AUTHKEY_LEN) return false;

	for (size_t i = 0; i < hexLen / 2; i++) {
		int hi = HexVal(line[i * 2]);
		int lo = HexVal(line[i * 2 + 1]);
		if (hi < 0 || lo < 0) return false;
		outKey[i] = (uint8_t)((hi << 4) | lo);
	}
	*outLen = hexLen / 2;
	return true;
}

void Qproto_Bans_Load()
{
	g_numBans = 0;

	// Same search order as qproto.cfg. If missing, g_path defaults to
	// addons/qproto/qproto_bans.cfg so new bans from the API land next to the .so.
	FILE* f = Qproto_OpenDataFile("qproto_bans.cfg", g_path, sizeof(g_path));
	if (!f) {
		Qproto_Log("qproto_bans.cfg not found - HW-id ban list empty (new bans → %s)", g_path);
		return;
	}

	char line[512];
	int lineNo = 0;
	while (fgets(line, sizeof(line), f)) {
		lineNo++;

		char* hash = strchr(line, '#');
		if (hash) *hash = '\0';

		char* p = SkipSpaces(line);
		RTrim(p);
		if (!*p) continue;

		if (g_numBans >= kMaxBans) {
			Qproto_Log("qproto_bans.cfg: hit the %d-entry limit - remaining lines ignored", kMaxBans);
			break;
		}

		size_t len;
		if (!Qproto_Bans_ParseHexLine(p, g_bans[g_numBans].key, &len)) {
			Qproto_Log("qproto_bans.cfg:%d: '%s' is not a valid hex key - skipped", lineNo, p);
			continue;
		}

		g_bans[g_numBans].len = len;
		g_numBans++;
	}
	fclose(f);

	Qproto_Log("qproto_bans.cfg loaded from %s: %d key(s)", g_path, g_numBans);
}

bool Qproto_Bans_IsBanned(const uint8_t* key, size_t len)
{
	if (!key || len == 0) return false;
	return FindBan(key, len) >= 0;
}

bool Qproto_Bans_Add(const uint8_t* key, size_t len)
{
	if (!key || len == 0 || len > MAX_AUTHKEY_LEN) return false;
	if (FindBan(key, len) >= 0) return false; // already banned
	if (g_numBans >= kMaxBans) {
		Qproto_Log("qproto_bans.cfg: cannot ban - hit the %d-entry limit", kMaxBans);
		return false;
	}

	BanEntry& entry = g_bans[g_numBans++];
	memcpy(entry.key, key, len);
	entry.len = len;

	char hex[MAX_AUTHKEY_LEN * 2 + 1];
	HexEncode(key, len, hex);

	if (g_path[0]) {
		FILE* f = fopen(g_path, "a");
		if (f) {
			fprintf(f, "%s\n", hex);
			fclose(f);
		}
	}

	Qproto_Log("banned raw auth key: %s (now %d total)", hex, g_numBans);
	return true;
}

bool Qproto_Bans_Remove(const uint8_t* key, size_t len)
{
	int idx = FindBan(key, len);
	if (idx < 0) return false;

	char hex[MAX_AUTHKEY_LEN * 2 + 1];
	HexEncode(g_bans[idx].key, g_bans[idx].len, hex);

	g_bans[idx] = g_bans[g_numBans - 1];
	g_numBans--;

	RewriteFile();

	Qproto_Log("unbanned raw auth key: %s (now %d total)", hex, g_numBans);
	return true;
}
