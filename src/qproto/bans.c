#include "qproto/bans.h"
#include "qproto/logger.h"
#include "qproto/paths.h"
#include "qproto/shared.h"

#include <stdio.h>
#include <string.h>

enum { k_max_bans = 512 };

typedef struct ban_entry {
	uint8_t key[MAX_AUTHKEY_LEN];
	size_t len;
} ban_entry_t;

static ban_entry_t g_bans[k_max_bans];
static int g_num_bans;
static char g_path[512];

static int
hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static void
hex_encode(const uint8_t *data, size_t len, char *out)
{
	size_t i;
	for (i = 0; i < len; i++) {
		snprintf(out + i * 2, 3, "%02x", data[i]);
	}
	out[len * 2] = '\0';
}

static char *
skip_spaces(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static void
rtrim(char *s)
{
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
		s[--n] = '\0';
	}
}

static int
find_ban(const uint8_t *key, size_t len)
{
	int i;
	for (i = 0; i < g_num_bans; i++) {
		if (g_bans[i].len == len && memcmp(g_bans[i].key, key, len) == 0)
			return i;
	}
	return -1;
}

static void
rewrite_file(void)
{
	FILE *f;
	int i;

	if (!g_path[0])
		return;

	f = fopen(g_path, "w");
	if (!f) {
		authum_logger_info(&g_qproto_logger, "qproto_bans.cfg: failed to rewrite %s - bans kept in memory only until next restart", g_path);
		return;
	}

	fprintf(f, "# Raw auth key bans (HDD serial / volume id / sXe hardware id), one hex-encoded\n");
	fprintf(f, "# key per line. Rewritten automatically by qproto (qproto_ban_authkey/qproto_unban_authkey,\n");
	fprintf(f, "# see qproto/api.h) - hand edits survive until the next ban/unban triggers another rewrite.\n");
	for (i = 0; i < g_num_bans; i++) {
		char hex[MAX_AUTHKEY_LEN * 2 + 1];
		hex_encode(g_bans[i].key, g_bans[i].len, hex);
		fprintf(f, "%s\n", hex);
	}
	fclose(f);
}

int
qproto_bans_parse_hex_line(const char *line, uint8_t *out_key, size_t *out_len)
{
	size_t hex_len = strlen(line);
	size_t i;

	if (hex_len == 0 || hex_len % 2 != 0 || hex_len / 2 > MAX_AUTHKEY_LEN)
		return 0;

	for (i = 0; i < hex_len / 2; i++) {
		int hi = hex_val(line[i * 2]);
		int lo = hex_val(line[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return 0;
		out_key[i] = (uint8_t)((hi << 4) | lo);
	}
	*out_len = hex_len / 2;
	return 1;
}

void
qproto_bans_load(void)
{
	FILE *f;
	char line[512];
	int line_no = 0;

	g_num_bans = 0;

	f = qproto_open_data_file("qproto_bans.cfg", g_path, sizeof(g_path));
	if (!f) {
		authum_logger_info(&g_qproto_logger, "qproto_bans.cfg not found - HW-id ban list empty (new bans → %s)", g_path);
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		char *hash;
		char *p;
		size_t len;

		line_no++;

		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';

		p = skip_spaces(line);
		rtrim(p);
		if (!*p)
			continue;

		if (g_num_bans >= k_max_bans) {
			authum_logger_info(&g_qproto_logger, "qproto_bans.cfg: hit the %d-entry limit - remaining lines ignored", k_max_bans);
			break;
		}

		if (!qproto_bans_parse_hex_line(p, g_bans[g_num_bans].key, &len)) {
			authum_logger_info(&g_qproto_logger, "qproto_bans.cfg:%d: '%s' is not a valid hex key - skipped", line_no, p);
			continue;
		}

		g_bans[g_num_bans].len = len;
		g_num_bans++;
	}
	fclose(f);

	authum_logger_info(&g_qproto_logger, "qproto_bans.cfg loaded from %s: %d key(s)", g_path, g_num_bans);
}

int
qproto_bans_is_banned(const uint8_t *key, size_t len)
{
	if (!key || len == 0)
		return 0;
	return find_ban(key, len) >= 0;
}

int
qproto_bans_add(const uint8_t *key, size_t len)
{
	ban_entry_t *entry;
	char hex[MAX_AUTHKEY_LEN * 2 + 1];

	if (!key || len == 0 || len > MAX_AUTHKEY_LEN)
		return 0;
	if (find_ban(key, len) >= 0)
		return 0;
	if (g_num_bans >= k_max_bans) {
		authum_logger_info(&g_qproto_logger, "qproto_bans.cfg: cannot ban - hit the %d-entry limit", k_max_bans);
		return 0;
	}

	entry = &g_bans[g_num_bans++];
	memcpy(entry->key, key, len);
	entry->len = len;

	hex_encode(key, len, hex);

	if (g_path[0]) {
		FILE *f = fopen(g_path, "a");
		if (f) {
			fprintf(f, "%s\n", hex);
			fclose(f);
		}
	}

	authum_logger_info(&g_qproto_logger, "banned raw auth key: %s (now %d total)", hex, g_num_bans);
	return 1;
}

int
qproto_bans_remove(const uint8_t *key, size_t len)
{
	int idx = find_ban(key, len);
	char hex[MAX_AUTHKEY_LEN * 2 + 1];

	if (idx < 0)
		return 0;

	hex_encode(g_bans[idx].key, g_bans[idx].len, hex);

	g_bans[idx] = g_bans[g_num_bans - 1];
	g_num_bans--;

	rewrite_file();

	authum_logger_info(&g_qproto_logger, "unbanned raw auth key: %s (now %d total)", hex, g_num_bans);
	return 1;
}
