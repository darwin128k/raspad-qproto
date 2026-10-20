#ifndef QPROTO_CLIENT_STATE_H
#define QPROTO_CLIENT_STATE_H

#include <stdint.h>
#include <stddef.h>
#include "qproto/shared.h"

/*
 * Per-connected-client auth record. Populated when qproto_hook.c finishes
 * classifying a connect (native Steam or emulated). This record backs qproto/api.h.
 */
typedef struct qproto_client_record {
	int valid;
	int userid;				/* client_t::userid - what "kick #N" expects */
	int protocol;
	uint32_t ip_address;			/* USERID_t.clientip in-memory representation */
	client_auth_kind_t auth_kind;
	client_id_kind_t id_kind;		/* resolved cid_* outcome */
	uint32_t steam_id;			/* low 32 bits of USERID_t.m_SteamID */
	auth_key_kind_t auth_key_kind;
	uint8_t auth_key[MAX_AUTHKEY_LEN];
	size_t auth_key_len;			/* 0 for native Steam clients */
	char auth_id_string[32];		/* e.g. "STEAM_0:1:12345" */
	float connect_time;			/* engine pfnTime() at ClientConnect */
} qproto_client_record_t;

void qproto_client_state_set_pending(const qproto_client_record_t *rec);
void qproto_client_state_on_connect(int index, int userid, const char *auth_id_string, float connect_time);
void qproto_client_state_on_disconnect(int index);
const qproto_client_record_t *qproto_client_state_get(int index);

#endif /* QPROTO_CLIENT_STATE_H */
