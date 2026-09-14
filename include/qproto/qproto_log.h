#pragma once

// Same LoggingMode convention as dproto.cfg: a bitmask of qproto_log_mode values
// (rl_console=1, rl_logfile=2, rl_console|rl_logfile=3) - see qproto_shared.h.
// "console" here means the engine's own server console (SERVER_PRINT), independent
// of mp_logfile/engine log rotation; "logfile" is our own qproto.log, always
// somewhere predictable to look during debugging regardless of engine log settings.
void Qproto_Log_Init(int loggingMode);
void Qproto_Log_Close();
void Qproto_Log(const char* fmt, ...);
void Qproto_Log_HexDump(const char* label, const void* data, int len);
