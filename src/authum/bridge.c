#include <qproto/bridge.h>

#include <qproto/client/state.h>
#include <qproto/command.h>
#include <qproto/config.h>
#include <qproto/events.h>
#include <qproto/hook.h>
#include <qproto/host.h>
#include <qproto/logger.h>

#include <authum/host.h>
#include <authum/null.h>

authum_host_t g_qproto_host;

authum_bool_t
qproto_authum_start(authum_host_t *host)
{
    if (authum_null_eq(host))
    {
        return authum_bool_false;
    }

    g_qproto_host = *host;

    /* Host sink only until cfg loads logging_mode. */
    authum_logger_init(&g_qproto_logger, &g_qproto_host, authum_logger_sink_host, "qproto");

    if (authum_null_eq(authum_host_crypto(&g_qproto_host)) ||
        authum_null_eq(authum_host_engine(&g_qproto_host)) ||
        authum_null_eq(authum_host_env(&g_qproto_host)) ||
        authum_null_eq(authum_host_sandbox(&g_qproto_host)) ||
        authum_null_eq(authum_host_events(&g_qproto_host)) ||
        authum_null_eq(authum_host_commands(&g_qproto_host)))
    {
        authum_logger_error(
            &g_qproto_logger,
            "host facade incomplete (needs crypto/engine/env/sandbox/events/commands)");
        return authum_bool_false;
    }

    qproto_config_load();
    qproto_logger_start(&g_qproto_host, g_qproto_config.logging_sinks);
    authum_logger_info(&g_qproto_logger, "start — module dir: %s",
                       authum_path_as_cstr(authum_host_env_module(&g_qproto_host)));

    if (!qproto_client_state_start(authum_host_sandbox(&g_qproto_host)) || !qproto_events_start() ||
        !qproto_command_start(&g_qproto_host))
    {
        authum_logger_error(&g_qproto_logger,
                            "client registry / event subscriptions / commands FAILED");
        qproto_logger_stop();
        return authum_bool_false;
    }

    if (!qproto_hook_install())
    {
        authum_logger_error(&g_qproto_logger, "qproto_hook_install FAILED");
        qproto_logger_stop();
        return authum_bool_false;
    }
    authum_logger_info(&g_qproto_logger, "Steam_NotifyClientConnect hook installed");
    return authum_bool_true;
}

/* Subscriptions, commands and the sandbox (client table) are released by Authum after this. */
void
qproto_authum_stop(void)
{
    qproto_hook_remove();
    qproto_client_state_stop();
    authum_logger_info(&g_qproto_logger, "stop — hook removed");
    qproto_logger_stop();
    authum_host_clear(&g_qproto_host);
}
