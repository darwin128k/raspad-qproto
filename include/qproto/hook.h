#ifndef QPROTO_HOOK_H
#define QPROTO_HOOK_H

/*
 * Installs/removes the inline JMP detour on the engine's Steam_NotifyClientConnect,
 * and implements the replacement that falls back to qproto_authorizers.c when
 * native Steam validation fails.
 */

int
qproto_hook_install(void);
void
qproto_hook_remove(void);

#endif /* QPROTO_HOOK_H */
