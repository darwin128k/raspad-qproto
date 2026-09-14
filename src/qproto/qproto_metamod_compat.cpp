// Metamod-P's SDK headers (sdk_util.h -> util.h) call safevoid_vsnprintf(), which
// is normally implemented in metamod's own osdep.cpp - but that file also defines a
// pile of metamod-internal-only globals (meta_errno, DLFNAME, etc.) that only make
// sense inside the metamod.so binary itself, not inside a plugin. Rather than link
// osdep.cpp wholesale into qproto (and drag in symbols we don't own), reproduce just
// this one small, self-contained helper verbatim (from metamod-p v1.21p37's osdep.cpp).

#include <cstdio>
#include <cstdarg>
#include <cstddef>

void safevoid_vsnprintf(char* s, size_t n, const char* format, va_list ap)
{
	if (!s || n <= 0)
		return;

	if (!format || !*format) {
		s[0] = 0;
		return;
	}

	int res = vsnprintf(s, n, format, ap);

	// w32api returns -1 on too long write, glibc returns number of bytes it could
	// have written if there were enough space; neither reliably NUL-terminates.
	if (res < 0 || (size_t)res >= n)
		s[n - 1] = 0;
}
