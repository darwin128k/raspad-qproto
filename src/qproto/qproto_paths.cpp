#include <cmath>	// must precede extdll.h - see qproto_hook.cpp for why
#include <extdll.h>
#include <enginecallback.h>
#include "qproto/qproto_paths.h"

#include <cstdio>
#include <cstring>

FILE* Qproto_OpenDataFile(const char* name, char* outPath, size_t outPathLen)
{
	if (!name || !outPath || outPathLen == 0) return nullptr;

	char gameDir[256] = {};
	(*g_engfuncs.pfnGetGameDir)(gameDir);

	const char* patterns[] = {
		"%s/addons/qproto/%s",
		"%s/%s",
		"%s/../%s",
	};

	for (const char* pattern : patterns) {
		snprintf(outPath, outPathLen, pattern, gameDir, name);
		FILE* f = fopen(outPath, "r");
		if (f) return f;
	}

	// Default write location: next to the plugin.
	snprintf(outPath, outPathLen, "%s/addons/qproto/%s", gameDir, name);
	return nullptr;
}
