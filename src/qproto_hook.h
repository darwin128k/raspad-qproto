#pragma once

// Installs/removes the inline JMP detour on the engine's Steam_NotifyClientConnect,
// and implements the replacement that falls back to qproto_authorizers.cpp when
// native Steam validation fails. See qproto_hook.cpp for the full rationale - this
// mirrors exactly what was validated in hook_selftest.cpp (SV_GetIDString) and
// authorizers_selftest.cpp (RevEmu2013 ticket), just wired into one real plugin hook.

bool Qproto_Hook_Install();
void Qproto_Hook_Remove();
