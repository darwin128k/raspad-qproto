#include <cmath>	// must precede extdll.h - see qproto_hook.cpp for why
#include <extdll.h>
#include <enginecallback.h>
#include "qproto/qproto_log.h"
#include "qproto/qproto_shared.h"

#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <cstring>

namespace {
FILE* g_logFile;
int g_mode; // bitmask of qproto_log_mode
}

void Qproto_Log_Init(int loggingMode)
{
	g_mode = loggingMode;

	if (!(g_mode & rl_logfile) || g_logFile) return;

	char gameDir[256] = {};
	(*g_engfuncs.pfnGetGameDir)(gameDir);

	char path[512];
	snprintf(path, sizeof(path), "%s/addons/qproto/qproto.log", gameDir);

	g_logFile = fopen(path, "a");
	if (g_logFile) {
		setvbuf(g_logFile, nullptr, _IONBF, 0); // unbuffered - always flushed, safe if the server crashes
		time_t t = time(nullptr);
		fprintf(g_logFile, "\n---- qproto log opened %s", ctime(&t));
	}
}

void Qproto_Log_Close()
{
	if (g_logFile) {
		fclose(g_logFile);
		g_logFile = nullptr;
	}
}

void Qproto_Log(const char* fmt, ...)
{
	if (!(g_mode & (rl_console | rl_logfile))) return;

	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if ((g_mode & rl_logfile) && g_logFile) {
		time_t t = time(nullptr);
		struct tm* lt = localtime(&t);
		fprintf(g_logFile, "[%02d:%02d:%02d] %s\n", lt->tm_hour, lt->tm_min, lt->tm_sec, buf);
	}

	if (g_mode & rl_console) {
		char consoleBuf[1040];
		snprintf(consoleBuf, sizeof(consoleBuf), "[QPROTO] %s\n", buf);
		(*g_engfuncs.pfnServerPrint)(consoleBuf);
	}
}

void Qproto_Log_HexDump(const char* label, const void* data, int len)
{
	if (!(g_mode & (rl_console | rl_logfile))) return;

	const unsigned char* p = (const unsigned char*)data;
	Qproto_Log("%s (%d bytes):", label, len);

	char line[128];
	for (int i = 0; i < len; i += 16) {
		int pos = snprintf(line, sizeof(line), "  %04x: ", i);
		for (int j = 0; j < 16 && i + j < len; j++) {
			pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", p[i + j]);
		}
		Qproto_Log("%s", line);
	}
}
