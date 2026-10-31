#include <qproto/command.h>

#include <qproto/client/auth/kind.h>
#include <qproto/client/state.h>
#include <qproto/event.h>

#include <authum/command/def.h>
#include <authum/cstr.h>
#include <authum/null.h>

#include <string.h>
#include <time.h>

const authum_command_def_t g_qproto_commands[] = {
    {"info", "[#userid | index | name]", "how clients authenticated (protocol, ids, connect time)",
     qproto_command_info, authum_null},
};

authum_bool_t
qproto_command_start(const authum_host_t *host)
{
    return authum_host_command_add_all(host, g_qproto_commands,
                                       sizeof g_qproto_commands / sizeof g_qproto_commands[0]);
}

const qproto_client_info_t *
qproto_command_lookup(const authum_char_t *arg)
{
    qproto_client_query_t query;
    authum_i32_t number;

    if (authum_null_eq(arg) || arg[0] == '\0')
    {
        return authum_null;
    }
    memset(&query, 0, sizeof query);
    query.size = sizeof query;
    if (arg[0] == '#' && authum_cstr_parse_i32(arg + 1, &number) && number > 0)
    {
        query.userid = number;
    }
    else if (authum_cstr_parse_i32(arg, &number) && number > 0)
    {
        query.index = number;
    }
    else
    {
        authum_cstr_copy(query.name, sizeof query.name, arg);
    }
    return qproto_client_state_find(&query);
}

void
qproto_command_print_row(const authum_command_t *cmd, const qproto_client_info_t *info)
{
    authum_command_printf(cmd, "%3d %6d  %-14s p%-3d %-22s %s", (int)info->index, (int)info->userid,
                          qproto_client_auth_kind_name(info->auth_kind), (int)info->protocol,
                          info->auth_id, info->name);
}

void
qproto_command_print_detail(const authum_command_t *cmd, const qproto_client_info_t *info)
{
    const authum_byte_t *ip = (const authum_byte_t *)&info->ip_address;
    authum_char_t hex[qproto_client_long_authid_size * 2 + 1];
    authum_char_t when[32];
    time_t at = (time_t)info->connected_at;
    struct tm *tm = gmtime(&at);
    authum_usize_t i;

    for (i = 0u; i < qproto_client_long_authid_size; ++i)
    {
        hex[i * 2u] = "0123456789abcdef"[info->long_authid[i] >> 4];
        hex[i * 2u + 1u] = "0123456789abcdef"[info->long_authid[i] & 15u];
    }
    hex[qproto_client_long_authid_size * 2] = '\0';
    if (authum_null_eq(tm) || strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S UTC", tm) == 0u)
    {
        authum_cstr_copy(when, sizeof when, "?");
    }

    authum_command_printf(cmd, "slot      %d (userid #%d)", (int)info->index, (int)info->userid);
    authum_command_printf(cmd, "name      %s (at connect)", info->name);
    authum_command_printf(cmd, "protocol  %s (%d), net protocol %d",
                          qproto_client_auth_kind_name(info->auth_kind), (int)info->auth_kind,
                          (int)info->protocol);
    authum_command_printf(cmd, "auth id   %s (id kind %d, steam id %u)", info->auth_id,
                          (int)info->id_kind, (unsigned)info->steam_id);
    authum_command_printf(cmd, "key       kind %d, %u bytes", (int)info->auth_key_kind,
                          (unsigned)info->auth_key_len);
    authum_command_printf(cmd, "long id   %s", hex);
    authum_command_printf(cmd, "ip        %u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    authum_command_printf(cmd, "connected %s", when);
}

authum_bool_t
qproto_command_info(const authum_command_t *cmd, authum_ptr user)
{
    const qproto_client_info_t *info;
    authum_i32_t i;
    authum_usize_t n = 0u;

    (void)user;
    if (authum_command_get_argc(cmd) > 1u)
    {
        return authum_bool_false;
    }
    if (authum_command_get_argc(cmd) == 1u)
    {
        info = qproto_command_lookup(authum_command_get_argv(cmd, 0u));
        if (authum_null_eq(info))
        {
            authum_command_printf(cmd, "qproto: no client '%s'", authum_command_get_argv(cmd, 0u));
            return authum_bool_true;
        }
        qproto_command_print_detail(cmd, info);
        return authum_bool_true;
    }

    authum_command_printf(cmd, "%3s %6s  %-14s %-4s %-22s %s", "#", "userid", "protocol", "net",
                          "auth id", "name");
    for (i = 1; i <= QPROTO_MAX_PLAYERS; ++i)
    {
        info = qproto_client_state_get(i);
        if (authum_null_eq(info))
        {
            continue;
        }
        qproto_command_print_row(cmd, info);
        ++n;
    }
    authum_command_printf(cmd, "%u client(s)", (unsigned)n);
    return authum_bool_true;
}
