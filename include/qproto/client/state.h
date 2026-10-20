#ifndef QPROTO_CLIENT_STATE_H
#define QPROTO_CLIENT_STATE_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>
#include <authum/size.h>

#include <qproto/shared.h>

/*
 * Per-connected-client auth record. Populated when hook.c finishes classifying
 * a connect (native Steam or emulated). Backs qproto/api.h.
 */
struct qproto_client_record
{
	authum_bool_t valid;
	authum_i32_t userid; /* client_t::userid — what "kick #N" expects */
	authum_i32_t protocol;
	authum_u32_t ip_address; /* USERID_t.clientip in-memory representation */
	qproto_client_auth_kind_t auth_kind;
	qproto_client_id_kind_t id_kind; /* resolved cid_* outcome */
	authum_u32_t steam_id; /* low 32 bits of USERID_t.m_SteamID */
	qproto_auth_key_kind_t auth_key_kind;
	authum_byte_t auth_key[QPROTO_MAX_AUTHKEY_LEN];
	authum_usize_t auth_key_len; /* 0 for native Steam clients */
	authum_char_t auth_id_string[32]; /* e.g. "STEAM_0:1:12345" */
	float connect_time; /* engine pfnTime() at ClientConnect */
};
typedef struct qproto_client_record qproto_client_record_t;

void qproto_client_state_set_pending(const qproto_client_record_t *rec);
void qproto_client_state_on_connect(authum_i32_t index, authum_i32_t userid,
				    const authum_char_t *auth_id_string, float connect_time);
void qproto_client_state_on_disconnect(authum_i32_t index);
const qproto_client_record_t *qproto_client_state_get(authum_i32_t index);

#endif /* QPROTO_CLIENT_STATE_H */
