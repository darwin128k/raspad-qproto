#ifndef QPROTO_API_H
#define QPROTO_API_H

#include <stdint.h>
#include <stddef.h>

/*
 * qproto's public API surface: the one module that ends up knowing a non-Steam
 * client's real identity signal. Other plugins reach this via dlopen + dlsym.
 * Plain C, ABI-stable across compilers.
 */

#define QPROTO_API_VERSION_MAJOR 1
#define QPROTO_API_VERSION_MINOR 1

#define QPROTO_LONG_AUTHID_LEN 16

enum qproto_auth_kind {
	qproto_auth_kind_none = 0,
	qproto_auth_kind_steam,
	qproto_auth_kind_steam_pending,
	qproto_auth_kind_setti,
	qproto_auth_kind_no_steam_47,
	qproto_auth_kind_no_steam_48,
	qproto_auth_kind_old_revemu,
	qproto_auth_kind_revemu,
	qproto_auth_kind_sc2009,
	qproto_auth_kind_revemu_2013,
	qproto_auth_kind_sxei,
	qproto_auth_kind_vellum,
};
typedef enum qproto_auth_kind qproto_auth_kind_t;

enum qproto_key_kind {
	qproto_key_kind_none = 0,
	qproto_key_kind_hddsn,
	qproto_key_kind_volumeid,
	qproto_key_kind_fileid,
	qproto_key_kind_sxeid,
	qproto_key_kind_other,
};
typedef enum qproto_key_kind qproto_key_kind_t;

int qproto_api_get_version_major(void);
int qproto_api_get_version_minor(void);

qproto_auth_kind_t qproto_get_client_authkind(int index);
int qproto_get_client_protocol(int index);
int qproto_get_client_userid(int index);
int qproto_get_client_idkind(int index);
unsigned int qproto_get_client_steamid(int index);
size_t qproto_get_client_authid_string(int index, char *out_buf, size_t out_buf_len);
unsigned int qproto_get_client_ip(int index);
size_t qproto_format_ip(unsigned int ip, char *out_buf, size_t out_buf_len);
float qproto_get_client_connect_time(int index);
size_t qproto_get_client_authkey(int index, void *out_buf, size_t out_buf_len);
qproto_key_kind_t qproto_get_client_authkeykind(int index);
int qproto_get_client_long_authid(int index, unsigned char out[QPROTO_LONG_AUTHID_LEN]);

int qproto_ban_authkey(const void *key, size_t len);
int qproto_unban_authkey(const void *key, size_t len);
int qproto_is_authkey_banned(const void *key, size_t len);
int qproto_ban_client(int index);
int qproto_kick_client(int index, const char *reason);

#endif /* QPROTO_API_H */
