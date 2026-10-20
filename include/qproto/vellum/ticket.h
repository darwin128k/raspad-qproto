#ifndef QPROTO_VELLUM_TICKET_H
#define QPROTO_VELLUM_TICKET_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Vellum ticket v1 — GoldSrc connect blob emitted by raspad-revloader's
 * steamclient and parsed here as qproto_client_auth_kind_vellum. Distinct size/magic from every
 * RevEmu family (10 / 152 / 178 / 194 / 0x300) so this server can later
 * disable those and keep only the Vellum client.
 *
 * Keep wire layout in sync with raspad-revloader/src/common/vellum_ticket.h.
 */

#define VELLUM_TICKET_MAGIC   0x4D4C4C56u /* 'VLLM' little-endian */
#define VELLUM_TICKET_VERSION 1
#define VELLUM_IDENT_MAX      48

#pragma pack(push, 1)
typedef struct vellum_ticket {
	uint32_t magic;
	uint16_t version;
	uint16_t ident_len;
	uint32_t account_id;
	uint32_t checksum;
	char     ident[VELLUM_IDENT_MAX];
} vellum_ticket_t;
#pragma pack(pop)

static inline uint32_t
vellum_fnv1a(const void *data, size_t n, uint32_t h)
{
	const unsigned char *p = (const unsigned char *)data;
	size_t i;
	for (i = 0; i < n; i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
}

static inline uint32_t
vellum_checksum(const vellum_ticket_t *t)
{
	uint32_t h = 2166136261u;
	h = vellum_fnv1a(&t->magic, 4, h);
	h = vellum_fnv1a(&t->version, 2, h);
	h = vellum_fnv1a(&t->ident_len, 2, h);
	h = vellum_fnv1a(&t->account_id, 4, h);
	h = vellum_fnv1a(t->ident, VELLUM_IDENT_MAX, h);
	return h;
}

static inline uint32_t
vellum_account_id_from_ident(const char *ident, size_t ident_len)
{
	uint32_t h = vellum_fnv1a(ident, ident_len, 2166136261u);
	uint32_t id = (h << 1) & 0x7FFFFFFEu;
	return id ? id : 2u;
}

static inline int
vellum_fill_ticket(vellum_ticket_t *t, const char *ident, size_t ident_len)
{
	if (t == NULL || ident == NULL || ident_len == 0 || ident_len > VELLUM_IDENT_MAX) {
		return 0;
	}
	memset(t, 0, sizeof(*t));
	t->magic = VELLUM_TICKET_MAGIC;
	t->version = VELLUM_TICKET_VERSION;
	t->ident_len = (uint16_t)ident_len;
	t->account_id = vellum_account_id_from_ident(ident, ident_len);
	memcpy(t->ident, ident, ident_len);
	t->checksum = vellum_checksum(t);
	return 1;
}

static inline int
vellum_ticket_valid(const vellum_ticket_t *t, size_t ticket_len)
{
	if (t == NULL || ticket_len != sizeof(vellum_ticket_t)) {
		return 0;
	}
	if (t->magic != VELLUM_TICKET_MAGIC || t->version != VELLUM_TICKET_VERSION) {
		return 0;
	}
	if (t->ident_len == 0 || t->ident_len > VELLUM_IDENT_MAX) {
		return 0;
	}
	if (t->checksum != vellum_checksum(t)) {
		return 0;
	}
	if (t->account_id != vellum_account_id_from_ident(t->ident, t->ident_len)) {
		return 0;
	}
	return 1;
}

#endif /* QPROTO_VELLUM_TICKET_H */
