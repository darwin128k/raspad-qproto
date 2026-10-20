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

typedef enum {
	QPROTO_AUTH_NONE = 0,
	QPROTO_AUTH_STEAM,
	QPROTO_AUTH_STEAM_PENDING,
	QPROTO_AUTH_SETTI,
	QPROTO_AUTH_NO_STEAM_47,
	QPROTO_AUTH_NO_STEAM_48,
	QPROTO_AUTH_OLD_REVEMU,
	QPROTO_AUTH_REVEMU,
	QPROTO_AUTH_SC2009,
	QPROTO_AUTH_REVEMU_2013,
	QPROTO_AUTH_SXEI,
	QPROTO_AUTH_VELLUM,
} qproto_authkind_t;

typedef enum {
	QPROTO_KEY_NONE = 0,
	QPROTO_KEY_HDDSN,
	QPROTO_KEY_VOLUMEID,
	QPROTO_KEY_FILEID,
	QPROTO_KEY_SXEID,
	QPROTO_KEY_OTHER,
} qproto_keykind_t;

int qproto_api_get_version_major(void);
int qproto_api_get_version_minor(void);

qproto_authkind_t qproto_get_client_authkind(int index);
int qproto_get_client_protocol(int index);
int qproto_get_client_userid(int index);
int qproto_get_client_idkind(int index);
unsigned int qproto_get_client_steamid(int index);
size_t qproto_get_client_authid_string(int index, char *out_buf, size_t out_buf_len);
unsigned int qproto_get_client_ip(int index);
size_t qproto_format_ip(unsigned int ip, char *out_buf, size_t out_buf_len);
float qproto_get_client_connect_time(int index);
size_t qproto_get_client_authkey(int index, void *out_buf, size_t out_buf_len);
qproto_keykind_t qproto_get_client_authkeykind(int index);
int qproto_get_client_long_authid(int index, unsigned char out[QPROTO_LONG_AUTHID_LEN]);

int qproto_ban_authkey(const void *key, size_t len);
int qproto_unban_authkey(const void *key, size_t len);
int qproto_is_authkey_banned(const void *key, size_t len);
int qproto_ban_client(int index);
int qproto_kick_client(int index, const char *reason);

#endif /* QPROTO_API_H */
