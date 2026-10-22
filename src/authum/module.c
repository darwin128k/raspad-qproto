#include <qproto/bridge.h>

#include <authum/client.h>

AUTHUM_MODULE_EXPORT const authum_module_api_t authum_module_api = {
    .start = qproto_authum_start,
    .stop = qproto_authum_stop,
};
