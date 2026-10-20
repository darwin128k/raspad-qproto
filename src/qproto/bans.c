#include <qproto/bans.h>
#include <qproto/logger.h>
#include <qproto/paths.h>
#include <qproto/shared.h>

#include <authum/null.h>
#include <authum/path.h>
#include <stdio.h>
#include <string.h>

enum { k_max_bans = 512 };

struct ban_entry
{
	authum_byte_t key[QPROTO_MAX_AUTHKEY_LEN];
	authum_usize_t len;
};
typedef struct ban_entry ban_entry_t;

static ban_entry_t g_bans[k_max_bans];
static authum_i32_t g_num_bans;
static authum_path_t g_path;

static authum_i32_t
hex_val(authum_char_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void
hex_encode(const authum_byte_t *data, authum_usize_t len, authum_char_t *out)
{
	authum_usize_t i;
	for (i = 0u; i < len; i++) {
		snprintf(out + i * 2u, 3, "%02x", data[i]);
	}
	out[len * 2u] = '\0';
}

static authum_char_t *
skip_spaces(authum_char_t *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static void
rtrim(authum_char_t *s)
{
	authum_usize_t n = (authum_usize_t)strlen(s);
	while (n > 0u &&
	       (s[n - 1u] == '\n' || s[n - 1u] == '\r' || s[n - 1u] == ' ' || s[n - 1u] == '\t')) {
		s[--n] = '\0';
	}
}

static authum_i32_t
find_ban(const authum_byte_t *key, authum_usize_t len)
{
	authum_i32_t i;
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
	authum_i32_t i;

	if (authum_path_is_empty(&g_path))
		return;

	f = fopen(authum_path_as_cstr(&g_path), "w");
	if (authum_null_eq(f)) {
		authum_logger_info(&g_qproto_logger,
				   "qproto_bans.cfg: failed to rewrite %s - bans kept in memory only until next restart",
				   authum_path_as_cstr(&g_path));
		return;
	}

	fprintf(f, "# Raw auth key bans (HDD serial / volume id / sXe hardware id), one hex-encoded\n");
	fprintf(f, "# key per line. Rewritten automatically by qproto (qproto_ban_authkey/qproto_unban_authkey,\n");
	fprintf(f, "# see qproto/api.h) - hand edits survive until the next ban/unban triggers another rewrite.\n");
	for (i = 0; i < g_num_bans; i++) {
		authum_char_t hex[QPROTO_MAX_AUTHKEY_LEN * 2 + 1];
		hex_encode(g_bans[i].key, g_bans[i].len, hex);
		fprintf(f, "%s\n", hex);
	}
	fclose(f);
}

authum_bool_t
qproto_bans_parse_hex_line(const authum_char_t *line, authum_byte_t *out_key, authum_usize_t *out_len)
{
	authum_usize_t hex_len = (authum_usize_t)strlen(line);
	authum_usize_t i;

	if (hex_len == 0u || hex_len % 2u != 0u || hex_len / 2u > QPROTO_MAX_AUTHKEY_LEN)
		return authum_bool_false;

	for (i = 0u; i < hex_len / 2u; i++) {
		authum_i32_t hi = hex_val(line[i * 2u]);
		authum_i32_t lo = hex_val(line[i * 2u + 1u]);
		if (hi < 0 || lo < 0)
			return authum_bool_false;
		out_key[i] = (authum_byte_t)((hi << 4) | lo);
	}
	*out_len = hex_len / 2u;
	return authum_bool_true;
}

void
qproto_bans_load(void)
{
	FILE *f;
	authum_char_t line[512];
	authum_i32_t line_no = 0;

	g_num_bans = 0;
	authum_path_clear(&g_path);

	f = qproto_open_data_file("qproto_bans.cfg", &g_path);
	if (authum_null_eq(f)) {
		authum_logger_info(&g_qproto_logger,
				   "qproto_bans.cfg not found - HW-id ban list empty (new bans → %s)",
				   authum_path_as_cstr(&g_path));
		return;
	}

	while (fgets(line, (int)sizeof(line), f)) {
		authum_char_t *hash;
		authum_char_t *p;
		authum_usize_t len;

		line_no++;

		hash = strchr(line, '#');
		if (!authum_null_eq(hash))
			*hash = '\0';

		p = skip_spaces(line);
		rtrim(p);
		if (!*p)
			continue;

		if (g_num_bans >= k_max_bans) {
			authum_logger_info(&g_qproto_logger,
					   "qproto_bans.cfg: hit the %d-entry limit - remaining lines ignored",
					   k_max_bans);
			break;
		}

		if (!qproto_bans_parse_hex_line(p, g_bans[g_num_bans].key, &len)) {
			authum_logger_info(&g_qproto_logger,
					   "qproto_bans.cfg:%d: '%s' is not a valid hex key - skipped", line_no, p);
			continue;
		}

		g_bans[g_num_bans].len = len;
		g_num_bans++;
	}
	fclose(f);

	authum_logger_info(&g_qproto_logger, "qproto_bans.cfg loaded from %s: %d key(s)",
			   authum_path_as_cstr(&g_path), g_num_bans);
}

authum_bool_t
qproto_bans_is_banned(const authum_byte_t *key, authum_usize_t len)
{
	if (authum_null_eq(key) || len == 0u)
		return authum_bool_false;
	return find_ban(key, len) >= 0 ? authum_bool_true : authum_bool_false;
}

authum_bool_t
qproto_bans_add(const authum_byte_t *key, authum_usize_t len)
{
	ban_entry_t *entry;
	authum_char_t hex[QPROTO_MAX_AUTHKEY_LEN * 2 + 1];

	if (authum_null_eq(key) || len == 0u || len > QPROTO_MAX_AUTHKEY_LEN)
		return authum_bool_false;
	if (find_ban(key, len) >= 0)
		return authum_bool_false;
	if (g_num_bans >= k_max_bans) {
		authum_logger_info(&g_qproto_logger, "qproto_bans.cfg: cannot ban - hit the %d-entry limit",
				   k_max_bans);
		return authum_bool_false;
	}

	entry = &g_bans[g_num_bans++];
	memcpy(entry->key, key, len);
	entry->len = len;

	hex_encode(key, len, hex);

	if (!authum_path_is_empty(&g_path)) {
		FILE *f = fopen(authum_path_as_cstr(&g_path), "a");
		if (!authum_null_eq(f)) {
			fprintf(f, "%s\n", hex);
			fclose(f);
		}
	}

	authum_logger_info(&g_qproto_logger, "banned raw auth key: %s (now %d total)", hex, g_num_bans);
	return authum_bool_true;
}

authum_bool_t
qproto_bans_remove(const authum_byte_t *key, authum_usize_t len)
{
	authum_i32_t idx = find_ban(key, len);
	authum_char_t hex[QPROTO_MAX_AUTHKEY_LEN * 2 + 1];

	if (idx < 0)
		return authum_bool_false;

	hex_encode(g_bans[idx].key, g_bans[idx].len, hex);

	g_bans[idx] = g_bans[g_num_bans - 1];
	g_num_bans--;

	rewrite_file();

	authum_logger_info(&g_qproto_logger, "unbanned raw auth key: %s (now %d total)", hex, g_num_bans);
	return authum_bool_true;
}
