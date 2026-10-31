/*
 * Vellum v2: signed tickets, server binding, clock window, key pins, v1 refusal.
 */

#include <qproto/authorizers.h>
#include <qproto/config.h>
#include <qproto/host.h>
#include <qproto/vellum/address.h>
#include <qproto/vellum/keystore.h>
#include <qproto/vellum/ticket.h>

#include <authum/crypto/ed25519.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)
#    include <direct.h>
#    define test_rmdir _rmdir
#else
#    include <unistd.h>
#    define test_rmdir rmdir
#endif

/** Remove @p path and then the directory that holds it: Windows has no `remove` for a directory. */
static void
test_remove_data(const char *path, const char *directory)
{
    remove(path);
    test_rmdir(directory);
}

int g_failures;
int g_total;

#define CHECK(cond)                                                                                \
    do                                                                                             \
    {                                                                                              \
        ++g_total;                                                                                 \
        if (!(cond))                                                                               \
        {                                                                                          \
            ++g_failures;                                                                          \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);               \
        }                                                                                          \
    } while (0)

/* authorizers.c reads these; the module defines them in config.c / bridge.c. */
qproto_config_t g_qproto_config;
authum_host_t g_qproto_host;

enum
{
    TEST_IP = 0x01020304, /* 1.2.3.4 */
    TEST_PORT = 27015,
    TEST_NOW = 1793000000
};

static const authum_u32_t g_server_ips[] = {TEST_IP};

typedef struct test_key
{
    authum_byte_t secret_key[AUTHUM_CRYPTO_ED25519_SECRET_KEY_SIZE];
    authum_byte_t public_key[AUTHUM_CRYPTO_ED25519_PUBLIC_KEY_SIZE];
} test_key_t;

void
make_key(test_key_t *key, authum_byte_t fill)
{
    authum_byte_t seed[AUTHUM_CRYPTO_ED25519_SEED_SIZE];

    memset(seed, fill, sizeof seed);
    authum_crypto_ed25519_create_key_pair(key->secret_key, key->public_key, seed);
}

void
make_ticket(vellum_ticket_t *t, const test_key_t *key, uint32_t ip, uint16_t port, uint64_t ts)
{
    vellum_ticket_prepare(t, ip, port, ts, key->public_key);
    authum_crypto_ed25519_sign(t->signature, key->secret_key, (const authum_byte_t *)t,
                               (authum_usize_t)VELLUM_TICKET_SIGNED_SIZE);
}

void
make_authdata(qproto_authdata_t *a, const void *ticket, size_t len)
{
    memset(a, 0, sizeof *a);
    a->auth_ticket = (const authum_byte_t *)ticket;
    a->ticket_len = (authum_usize_t)len;
    a->protocol = 48;
    a->server_ips = g_server_ips;
    a->server_ip_count = 1u;
    a->server_port = TEST_PORT;
    a->now = TEST_NOW;
}

qproto_client_auth_kind_t
authorize(const void *ticket, size_t len, qproto_authdata_t *a)
{
    make_authdata(a, ticket, len);
    return qproto_authorize_client(a, authum_bool_true, authum_bool_true);
}

void
reset_config(void)
{
    memset(&g_qproto_config, 0, sizeof g_qproto_config);
    g_qproto_config.enable_vellum = authum_bool_true;
    g_qproto_config.vellum_max_clock_skew = 86400u;
}

void
test_accept(void)
{
    test_key_t key;
    vellum_ticket_t t;
    qproto_authdata_t a;

    reset_config();
    qproto_vellum_keystore_open(authum_null);
    make_key(&key, 1);
    make_ticket(&t, &key, TEST_IP, TEST_PORT, TEST_NOW - 60);

    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_vellum);
    CHECK(!a.rejected);
    CHECK(a.steam_id == vellum_account_id_from_key(key.public_key));
    CHECK(a.steam_id >= 2u);
    CHECK(a.auth_key_len == VELLUM_PUBLIC_KEY_SIZE);
    CHECK(memcmp(a.auth_key, key.public_key, VELLUM_PUBLIC_KEY_SIZE) == 0);
    CHECK(qproto_vellum_keystore_count() == 1u);

    /* Reconnect with the same key: still fine, nothing new pinned. */
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_vellum);
    CHECK(qproto_vellum_keystore_count() == 1u);

    /* Server that does not know its address/clock checks only the signature. */
    make_ticket(&t, &key, 0x0A000001, 1, 0);
    make_authdata(&a, &t, sizeof t);
    a.server_ip_count = 0u;
    a.server_port = 0u;
    a.now = 0;
    CHECK(qproto_vellum_authorize(&a) == qproto_client_auth_kind_vellum);
    qproto_vellum_keystore_close();
}

void
test_reject(void)
{
    test_key_t key;
    vellum_ticket_t t;
    qproto_authdata_t a;
    authum_byte_t v1[VELLUM_TICKET_V1_SIZE];
    uint32_t magic = VELLUM_TICKET_MAGIC;
    uint16_t version = VELLUM_TICKET_V1_VERSION;

    reset_config();
    qproto_vellum_keystore_open(authum_null);
    make_key(&key, 2);

    /* v1 is refused outright вЂ” not handed to the NoSteam catch-all. */
    memset(v1, 0, sizeof v1);
    memcpy(v1, &magic, sizeof magic);
    memcpy(v1 + sizeof magic, &version, sizeof version);
    CHECK(authorize(v1, sizeof v1, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected);
    CHECK(strstr(a.reject_reason, "v1") != NULL);

    /* Tampered after signing. */
    make_ticket(&t, &key, TEST_IP, TEST_PORT, TEST_NOW);
    t.server_port = TEST_PORT + 1;
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected && strstr(a.reject_reason, "signature") != NULL);

    /* Honestly signed, but for another server. */
    make_ticket(&t, &key, TEST_IP, TEST_PORT + 1, TEST_NOW);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected && strstr(a.reject_reason, "port") != NULL);
    make_ticket(&t, &key, 0x05060708, TEST_PORT, TEST_NOW);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected && strstr(a.reject_reason, "5.6.7.8") != NULL);

    /* Clock window, both directions. */
    make_ticket(&t, &key, TEST_IP, TEST_PORT, TEST_NOW - 86401);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected && strstr(a.reject_reason, "clock") != NULL);
    make_ticket(&t, &key, TEST_IP, TEST_PORT, TEST_NOW + 86401);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected);
    make_ticket(&t, &key, TEST_IP, TEST_PORT, TEST_NOW + 86400);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_vellum);

    /* Reserved fields must stay zero (and are signed). */
    make_ticket(&t, &key, TEST_IP, TEST_PORT, TEST_NOW);
    t.flags = 1;
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected && strstr(a.reject_reason, "malformed") != NULL);

    /* Not Vellum at all: no rejection, other authorizers get a go. */
    CHECK(authorize("\x01\x02\x03", 3, &a) == qproto_client_auth_kind_no_steam_48);
    CHECK(!a.rejected);

    /* enable_vellum = 0: Vellum blobs are just unknown tickets again. */
    g_qproto_config.enable_vellum = authum_bool_false;
    CHECK(authorize(v1, sizeof v1, &a) == qproto_client_auth_kind_no_steam_48);
    qproto_vellum_keystore_close();
}

void
test_pins(void)
{
    test_key_t owner;
    test_key_t thief;
    vellum_ticket_t t;
    qproto_authdata_t a;
    authum_u32_t id;
    char path[] = "qproto_test_vellum_keys.txt";
    FILE *f;

    reset_config();
    remove(path);
    make_key(&owner, 3);
    make_key(&thief, 4);
    id = vellum_account_id_from_key(owner.public_key);

    CHECK(qproto_vellum_keystore_open(path));
    CHECK(qproto_vellum_keystore_count() == 0u);
    CHECK(qproto_vellum_keystore_bind(id, owner.public_key) == qproto_vellum_bind_new);
    CHECK(qproto_vellum_keystore_bind(id, owner.public_key) == qproto_vellum_bind_known);
    /* Same id, another key вЂ” what a forger with a colliding key would hit. */
    CHECK(qproto_vellum_keystore_bind(id, thief.public_key) == qproto_vellum_bind_conflict);
    qproto_vellum_keystore_close();

    /* Pins survive a restart; comments and junk lines are ignored. */
    f = fopen(path, "a");
    CHECK(f != NULL);
    if (f)
    {
        fputs("# comment\nnot a pin\n", f);
        fclose(f);
    }
    CHECK(qproto_vellum_keystore_open(path));
    CHECK(qproto_vellum_keystore_count() == 1u);
    CHECK(qproto_vellum_keystore_bind(id, thief.public_key) == qproto_vellum_bind_conflict);

    /* Through the authorizer: the pinned owner gets in, a key clash does not. */
    make_ticket(&t, &owner, TEST_IP, TEST_PORT, TEST_NOW);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_vellum);
    qproto_vellum_keystore_close();

    CHECK(qproto_vellum_keystore_open(authum_null));
    CHECK(qproto_vellum_keystore_bind(vellum_account_id_from_key(thief.public_key),
                                      owner.public_key) == qproto_vellum_bind_new);
    make_ticket(&t, &thief, TEST_IP, TEST_PORT, TEST_NOW);
    CHECK(authorize(&t, sizeof t, &a) == qproto_client_auth_kind_unknown);
    CHECK(a.rejected && strstr(a.reject_reason, "pinned") != NULL);
    qproto_vellum_keystore_close();
    remove(path);
}

void
test_lazy_pin_directory(void)
{
    const char *directory = "qproto_test_lazy_data";
    const char *path = "qproto_test_lazy_data/vellum_keys.txt";
    struct stat info;
    test_key_t owner;
    authum_u32_t id;

    test_remove_data(path, directory);
    CHECK(stat(directory, &info) != 0);
    make_key(&owner, 7);
    id = vellum_account_id_from_key(owner.public_key);
    CHECK(qproto_vellum_keystore_open(path));
    CHECK(stat(directory, &info) != 0); /* Reading does not create data. */
    CHECK(qproto_vellum_keystore_bind(id, owner.public_key) == qproto_vellum_bind_new);
    CHECK(stat(path, &info) == 0); /* First write creates its parent through LH. */
    qproto_vellum_keystore_close();
    CHECK(qproto_vellum_keystore_open(path));
    CHECK(qproto_vellum_keystore_count() == 1u);
    CHECK(qproto_vellum_keystore_bind(id, owner.public_key) == qproto_vellum_bind_known);
    qproto_vellum_keystore_close();
    test_remove_data(path, directory);
}

void
test_address(void)
{
    authum_u32_t ips[QPROTO_VELLUM_MAX_SERVER_IPS];

    CHECK(qproto_vellum_parse_ip_list("1.2.3.4", ips, 4u) == 1u && ips[0] == 0x01020304u);
    CHECK(qproto_vellum_parse_ip_list(" 1.2.3.4 , 192.168.0.10", ips, 4u) == 2u &&
          ips[1] == 0xC0A8000Au);
    CHECK(qproto_vellum_parse_ip_list("localhost", ips, 4u) == 0u);
    CHECK(qproto_vellum_parse_ip_list("0.0.0.0,127.0.0.1", ips, 4u) == 0u);
    CHECK(qproto_vellum_parse_ip_list("1.2.3,256.1.1.1,1.2.3.4x,5.6.7.8", ips, 4u) == 1u &&
          ips[0] == 0x05060708u);
    CHECK(qproto_vellum_parse_ip_list("1.1.1.1,2.2.2.2,3.3.3.3", ips, 2u) == 2u);
    CHECK(qproto_vellum_parse_ip_list("", ips, 4u) == 0u);
    CHECK(qproto_vellum_parse_ip_list(NULL, ips, 4u) == 0u);
}

int
main(void)
{
    test_accept();
    test_reject();
    test_pins();
    test_lazy_pin_directory();
    test_address();
    printf("qproto_vellum: %d/%d checks passed\n", g_total - g_failures, g_total);
    return g_failures != 0;
}
