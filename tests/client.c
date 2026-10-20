/*
 * qproto client registry + long authid, with fake Authum sandbox / crypto ops.
 */

#include <qproto/client/long_authid.h>
#include <qproto/client/state.h>
#include <qproto/command.h>
#include <qproto/event.h>

#include <authum/commands.h>
#include <authum/cstr.h>
#include <authum/host.h>
#include <authum/null.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_failures;
int g_total;

#define CHECK(cond)                                                                    \
	do {                                                                           \
		++g_total;                                                             \
		if (!(cond)) {                                                         \
			++g_failures;                                                  \
			fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
				#cond);                                                \
		}                                                                      \
	} while (0)

authum_ptr
fake_sandbox_alloc(authum_ptr parent, authum_usize_t size)
{
	(void)parent;
	return calloc(1u, size > 0u ? size : 1u);
}

const authum_sandbox_ops_t g_fake_sandbox_ops = {
	.alloc = fake_sandbox_alloc,
};

authum_usize_t
fake_sha_hash(authum_crypto_sha_kind_t kind, authum_ptr data, authum_usize_t size, authum_ptr out,
	      authum_usize_t out_size)
{
	authum_byte_t *o = (authum_byte_t *)out;
	const authum_byte_t *d = (const authum_byte_t *)data;
	authum_usize_t i;

	(void)kind;
	memset(o, 0, out_size);
	for (i = 0u; i < size; ++i)
		o[i % out_size] ^= d[i];
	return AUTHUM_CRYPTO_SHA256_DIGEST_SIZE;
}

authum_event_client_t
make_connect(authum_i32_t index, authum_i32_t userid, const char *name)
{
	authum_event_client_t ev;

	memset(&ev, 0, sizeof ev);
	ev.size = sizeof ev;
	ev.index = index;
	ev.userid = userid;
	ev.allow = authum_bool_true;
	ev.unix_time = 1700000000;
	authum_cstr_copy(ev.name, sizeof ev.name, name);
	authum_cstr_copy(ev.auth_id, sizeof ev.auth_id, "STEAM_0:1:42");
	return ev;
}

void
test_bind_and_query(void)
{
	authum_sandbox_t sb = { &g_fake_sandbox_ops, (authum_ptr)&sb };
	qproto_client_info_t pending;
	qproto_client_info_t *bound;
	authum_event_client_t ev;
	qproto_client_query_t q;

	CHECK(qproto_client_state_start(&sb));

	/* Nothing pending (bot / HLTV): slot stays empty. */
	ev = make_connect(1, 10, "bot");
	CHECK(qproto_client_state_bind(&ev) == authum_null);
	CHECK(qproto_client_state_get(1) == authum_null);

	memset(&pending, 0, sizeof pending);
	pending.protocol = 48;
	pending.auth_kind = qproto_client_auth_kind_revemu_2013;
	pending.steam_id = 777u;
	qproto_client_state_set_pending(&pending);

	ev = make_connect(3, 55, "Player");
	bound = qproto_client_state_bind(&ev);
	CHECK(bound != authum_null);
	CHECK(bound->index == 3 && bound->userid == 55);
	CHECK(bound->auth_kind == qproto_client_auth_kind_revemu_2013);
	CHECK(bound->protocol == 48 && bound->steam_id == 777u);
	CHECK(strcmp(bound->name, "Player") == 0);
	CHECK(strcmp(bound->auth_id, "STEAM_0:1:42") == 0);
	CHECK(bound->connected_at == 1700000000);
	CHECK(bound->size == sizeof(qproto_client_info_t));

	/* Pending is consumed once. */
	ev = make_connect(4, 56, "Other");
	CHECK(qproto_client_state_bind(&ev) == authum_null);

	memset(&q, 0, sizeof q);
	q.size = sizeof q;
	q.index = 3;
	CHECK(qproto_client_state_find(&q) == qproto_client_state_get(3));

	memset(&q, 0, sizeof q);
	q.size = sizeof q;
	q.userid = 55;
	CHECK(qproto_client_state_find(&q) == qproto_client_state_get(3));

	memset(&q, 0, sizeof q);
	q.size = sizeof q;
	authum_cstr_copy(q.name, sizeof q.name, "player");
	CHECK(qproto_client_state_find(&q) == qproto_client_state_get(3));

	memset(&q, 0, sizeof q);
	q.size = sizeof q;
	q.userid = 99;
	CHECK(qproto_client_state_find(&q) == authum_null);

	qproto_client_state_clear(3);
	CHECK(qproto_client_state_get(3) == authum_null);

	/* Out-of-range slots are ignored. */
	CHECK(qproto_client_state_get(0) == authum_null);
	CHECK(qproto_client_state_get(QPROTO_MAX_PLAYERS + 1) == authum_null);
	qproto_client_state_clear(-1);

	qproto_client_state_stop();
	CHECK(qproto_client_state_get(1) == authum_null);
}

void
test_long_authid(void)
{
	authum_crypto_t crypto;
	qproto_client_info_t a;
	qproto_client_info_t b;

	memset(&crypto, 0, sizeof crypto);
	crypto.sha_hash = fake_sha_hash;

	memset(&a, 0, sizeof a);
	a.auth_key_len = 4u;
	memcpy(a.auth_key, "\x01\x02\x03\x04", 4u);
	CHECK(qproto_client_long_authid(&crypto, &a));
	CHECK(a.long_authid[0] == 0x01 && a.long_authid[3] == 0x04);

	memset(&b, 0, sizeof b);
	b.auth_kind = qproto_client_auth_kind_steam;
	b.steam_id = 0x11223344u;
	CHECK(qproto_client_long_authid(&crypto, &b));
	CHECK(b.long_authid[0] == (authum_byte_t)qproto_client_auth_kind_steam);

	CHECK(!qproto_client_long_authid(authum_null, &b));
	memset(&crypto, 0, sizeof crypto);
	CHECK(!qproto_client_long_authid(&crypto, &b));
}

char g_out[2048];
authum_usize_t g_added;

void
fake_print(authum_ptr out, const authum_char_t *text)
{
	(void)out;
	strncat(g_out, text, sizeof g_out - strlen(g_out) - 1u);
}

authum_bool_t
fake_command_add(authum_ptr owner, const authum_char_t *scope, const authum_command_def_t *def)
{
	(void)owner;
	if (strcmp(scope, "qproto") == 0 && def->fn != 0)
		++g_added;
	return authum_bool_true;
}

authum_command_t
make_command(authum_usize_t argc, const authum_char_t *const *argv)
{
	authum_command_t cmd;

	memset(&cmd, 0, sizeof cmd);
	cmd.size = sizeof cmd;
	cmd.scope = "qproto";
	cmd.name = "info";
	cmd.argc = argc;
	cmd.argv = argv;
	cmd.print = fake_print;
	return cmd;
}

void
test_command_info(void)
{
	authum_sandbox_t sb = { &g_fake_sandbox_ops, (authum_ptr)&sb };
	const authum_commands_ops_t ops = { .add = fake_command_add };
	authum_commands_t commands = { &ops, authum_null, "qproto" };
	authum_host_t host;
	qproto_client_info_t pending;
	authum_event_client_t ev;
	authum_command_t cmd;
	const authum_char_t *by_userid[] = { "#55" };
	const authum_char_t *by_slot[] = { "3" };
	const authum_char_t *by_name[] = { "PLAYER" };
	const authum_char_t *missing[] = { "nobody" };
	const authum_char_t *too_many[] = { "a", "b" };

	memset(&host, 0, sizeof host);
	authum_host_set_commands(&host, &commands);
	g_added = 0u;
	CHECK(qproto_command_start(&host));
	CHECK(g_added == 1u);

	CHECK(qproto_client_state_start(&sb));
	memset(&pending, 0, sizeof pending);
	pending.protocol = 48;
	pending.auth_kind = qproto_client_auth_kind_revemu_2013;
	pending.ip_address = 0x0100007Fu; /* 127.0.0.1 in memory order (little-endian) */
	qproto_client_state_set_pending(&pending);
	ev = make_connect(3, 55, "Player");
	CHECK(qproto_client_state_bind(&ev) != authum_null);

	CHECK(qproto_command_lookup("#55") == qproto_client_state_get(3));
	CHECK(qproto_command_lookup("3") == qproto_client_state_get(3));
	CHECK(qproto_command_lookup("player") == qproto_client_state_get(3));
	CHECK(qproto_command_lookup("#0") == authum_null);
	CHECK(qproto_command_lookup("") == authum_null);

	g_out[0] = '\0';
	cmd = make_command(0u, authum_null);
	CHECK(qproto_command_info(&cmd, authum_null));
	CHECK(strstr(g_out, "RevEmu2013") != authum_null);
	CHECK(strstr(g_out, "STEAM_0:1:42") != authum_null);
	CHECK(strstr(g_out, "1 client(s)") != authum_null);

	cmd = make_command(1u, by_userid);
	g_out[0] = '\0';
	CHECK(qproto_command_info(&cmd, authum_null));
	CHECK(strstr(g_out, "slot      3 (userid #55)") != authum_null);
	CHECK(strstr(g_out, "ip        127.0.0.1") != authum_null);
	CHECK(strstr(g_out, "connected 2023-11-14 22:13:20 UTC") != authum_null);

	cmd = make_command(1u, by_slot);
	g_out[0] = '\0';
	CHECK(qproto_command_info(&cmd, authum_null));
	CHECK(strstr(g_out, "name      Player") != authum_null);

	cmd = make_command(1u, by_name);
	g_out[0] = '\0';
	CHECK(qproto_command_info(&cmd, authum_null));
	CHECK(strstr(g_out, "RevEmu2013 (9)") != authum_null);

	cmd = make_command(1u, missing);
	g_out[0] = '\0';
	CHECK(qproto_command_info(&cmd, authum_null));
	CHECK(strcmp(g_out, "qproto: no client 'nobody'\n") == 0);

	/* Bad usage → false, Authum prints the usage line. */
	cmd = make_command(2u, too_many);
	CHECK(!qproto_command_info(&cmd, authum_null));

	qproto_client_state_stop();
}

int
main(void)
{
	test_bind_and_query();
	test_long_authid();
	test_command_info();
	printf("qproto_client: %d/%d checks passed\n", g_total - g_failures, g_total);
	return g_failures == 0 ? 0 : 1;
}
