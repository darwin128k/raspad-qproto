#include "qproto/qproto_data_dir.h"

#include <cstring>

namespace {

char g_data_dir[512];

} // namespace

void
qproto_set_data_dir(const char *dir)
{
	if (!dir || !dir[0]) {
		g_data_dir[0] = '\0';
		return;
	}
	strncpy(g_data_dir, dir, sizeof(g_data_dir) - 1u);
	g_data_dir[sizeof(g_data_dir) - 1u] = '\0';
}

const char *
qproto_get_data_dir(void)
{
	return g_data_dir[0] ? g_data_dir : nullptr;
}
