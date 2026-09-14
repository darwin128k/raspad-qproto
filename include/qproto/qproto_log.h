#pragma once

// Dedicated qproto log file - independent of mp_logfile/engine log rotation, so it's
// always somewhere predictable to look during debugging. Opened once at plugin load.
void Qproto_Log_Init();
void Qproto_Log_Close();
void Qproto_Log(const char* fmt, ...);
void Qproto_Log_HexDump(const char* label, const void* data, int len);
