#ifndef QPROTO_COMMAND_H
#define QPROTO_COMMAND_H

#include <authum/bool.h>
#include <authum/command.h>
#include <authum/host.h>

#include <qproto/client/info.h>

/*
 * Console / RCON commands, routed by Authum (`authum qproto …`). qproto never
 * registers engine commands itself.
 *
 *   authum qproto info                         every connected client, one line each
 *   authum qproto info <#userid | index | name>  one client in detail
 */

authum_bool_t
qproto_command_start(const authum_host_t *host);

authum_bool_t
qproto_command_info(const authum_command_t *cmd, authum_ptr user);

/* `#5` → userid 5, `5` → slot 5, anything else → connect name (case-insensitive). */
const qproto_client_info_t *
qproto_command_lookup(const authum_char_t *arg);

void
qproto_command_print_row(const authum_command_t *cmd, const qproto_client_info_t *info);
void
qproto_command_print_detail(const authum_command_t *cmd, const qproto_client_info_t *info);

#endif /* QPROTO_COMMAND_H */
