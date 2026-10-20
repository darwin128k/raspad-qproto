#include "host_engine.h"
#include "host_log.h"
#include "qproto/qproto_data_dir.h"
#include "qproto/qproto_log.h"
#include "qproto/qproto_shared.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

static FILE *g_log_file;
static int g_mode;
static char g_log_path[512];

void
qproto_log_init(int logging_mode)
{
	char note[640];

	g_mode = logging_mode;

	if (!(g_mode & rl_logfile) || g_log_file)
		return;

	{
		const char *mod_dir = qproto_get_data_dir();
		if (mod_dir) {
			snprintf(g_log_path, sizeof(g_log_path), "%s/qproto.log", mod_dir);
		} else {
			char game_dir[256];
			memset(game_dir, 0, sizeof(game_dir));
			authum_engine_get_game_dir(qproto_host_engine(), game_dir, sizeof game_dir);
			snprintf(g_log_path, sizeof(g_log_path), "%s/addons/authum/modules/qproto/qproto.log",
				 game_dir);
		}
	}

	g_log_file = fopen(g_log_path, "a");
	if (g_log_file) {
		setvbuf(g_log_file, NULL, _IONBF, 0);
		{
			time_t t = time(NULL);
			fprintf(g_log_file, "\n---- qproto (Authum module) log opened %s", ctime(&t));
		}
		if (g_mode & rl_host) {
			snprintf(note, sizeof(note), "[qproto] qproto.log opened: %s", g_log_path);
			qproto_host_log(0, note);
		}
	} else if (g_mode & rl_host) {
		snprintf(note, sizeof(note), "[qproto] qproto.log open FAILED: %s", g_log_path);
		qproto_host_log(1, note);
	}
}

void
qproto_log_close(void)
{
	if (g_log_file) {
		fclose(g_log_file);
		g_log_file = NULL;
	}
}

void
qproto_log(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (!(g_mode & (rl_console | rl_logfile | rl_host)))
		return;

	if (g_mode & rl_host) {
		char host_line[1100];
		snprintf(host_line, sizeof(host_line), "[qproto] %s", buf);
		qproto_host_log(0, host_line);
	}

	if ((g_mode & rl_logfile) && g_log_file) {
		time_t t = time(NULL);
		struct tm *lt = localtime(&t);
		fprintf(g_log_file, "[%02d:%02d:%02d] %s\n", lt->tm_hour, lt->tm_min, lt->tm_sec, buf);
	}

	if (g_mode & rl_console) {
		char console_buf[1040];
		snprintf(console_buf, sizeof(console_buf), "[QPROTO] %s\n", buf);
		authum_engine_server_print(qproto_host_engine(), console_buf);
	}
}

void
qproto_log_hex_dump(const char *label, const void *data, int len)
{
	const unsigned char *p;
	char line[128];
	int i;

	if (!(g_mode & (rl_console | rl_logfile | rl_host)))
		return;

	p = (const unsigned char *)data;
	qproto_log("%s (%d bytes):", label, len);

	for (i = 0; i < len; i += 16) {
		int pos = snprintf(line, sizeof(line), "  %04x: ", i);
		int j;
		for (j = 0; j < 16 && i + j < len; j++) {
			pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", p[i + j]);
		}
		qproto_log("%s", line);
	}
}
