#pragma once

// LoggingMode: rl_console=1, rl_logfile=2, rl_host=4 — see qproto_shared.h.
void qproto_log_init(int logging_mode);
void qproto_log_close();
void qproto_log(const char *fmt, ...);
void qproto_log_hex_dump(const char *label, const void *data, int len);
