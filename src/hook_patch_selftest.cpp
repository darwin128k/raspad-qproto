// Step 1 of the hook self-test: dlopen() the real engine_i486.so, call the real
// (unpatched) SV_GetIDString to get a baseline, install a 5-byte JMP detour at its
// entry point (mprotect + write 0xE9 + rel32, same technique dproto's binary uses),
// confirm our replacement gets called instead, then restore the original bytes and
// confirm the real function works again. No running server involved - this only
// proves the patch mechanism itself is sound against the real binary.

#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>

enum AUTH_IDTYPE { AUTH_IDTYPE_UNKNOWN = 0, AUTH_IDTYPE_STEAM = 1, AUTH_IDTYPE_VALVE = 2, AUTH_IDTYPE_LOCAL = 3 };

struct USERID_t
{
	int idtype;
	uint64_t m_SteamID;
	unsigned int clientip;
};

typedef char* (*SV_GetIDString_t)(USERID_t*);

static SV_GetIDString_t g_real_SV_GetIDString;
static unsigned char g_savedBytes[5];
static void* g_hookTarget;

// Our replacement. Matches the real function's signature/calling convention exactly
// (cdecl, single pointer arg) since it's what gets jumped to directly.
char* Qproto_SV_GetIDString_hook(USERID_t* id)
{
	static char buf[64];
	snprintf(buf, sizeof(buf), "QPROTO_HOOKED(idtype=%d)", id->idtype);
	return buf;
}

static void PatchJmp(void* target, void* dest, unsigned char* saveBack)
{
	uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
	size_t len = ((uintptr_t)target + 5) - page;
	mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);

	if (saveBack) memcpy(saveBack, target, 5);

	unsigned char* t = (unsigned char*)target;
	int32_t rel = (int32_t)((uintptr_t)dest - (uintptr_t)target - 5);
	t[0] = 0xE9;
	memcpy(t + 1, &rel, 4);
}

static void Unpatch(void* target, const unsigned char* saved)
{
	uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
	size_t len = ((uintptr_t)target + 5) - page;
	mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy(target, saved, 5);
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s /path/to/engine_i486.so\n", argv[0]);
		return 2;
	}

	void* h = dlopen(argv[1], RTLD_NOW);
	if (!h) {
		printf("dlopen failed: %s\n", dlerror());
		return 1;
	}

	void* sym = dlsym(h, "SV_GetIDString");
	if (!sym) {
		printf("dlsym(SV_GetIDString) failed: %s\n", dlerror());
		return 1;
	}
	g_real_SV_GetIDString = (SV_GetIDString_t)sym;
	g_hookTarget = sym;

	USERID_t id = {};
	id.idtype = AUTH_IDTYPE_VALVE;
	id.m_SteamID = 0x1122334455667788ULL;
	id.clientip = 0x0100007F; // 127.0.0.1

	printf("--- baseline call (unpatched) ---\n");
	char* r1 = g_real_SV_GetIDString(&id);
	printf("[%s] real SV_GetIDString returned: '%s'\n", r1 ? "OK" : "FAIL", r1 ? r1 : "(null)");

	printf("--- installing JMP detour ---\n");
	PatchJmp(g_hookTarget, (void*)&Qproto_SV_GetIDString_hook, g_savedBytes);

	char* r2 = g_real_SV_GetIDString(&id); // same pointer, now redirected
	bool hookHit = r2 && strncmp(r2, "QPROTO_HOOKED", 13) == 0;
	printf("[%s] patched call returned: '%s'\n", hookHit ? "OK" : "FAIL", r2 ? r2 : "(null)");

	printf("--- restoring original bytes ---\n");
	Unpatch(g_hookTarget, g_savedBytes);

	char* r3 = g_real_SV_GetIDString(&id);
	bool restored = r3 && r1 && strcmp(r1, r3) == 0;
	printf("[%s] post-restore call returned: '%s' (matches baseline: %s)\n",
		restored ? "OK" : "FAIL", r3 ? r3 : "(null)", restored ? "yes" : "no");

	int failures = (r1 == nullptr) + !hookHit + !restored;
	printf(failures == 0 ? "ALL TESTS PASSED\n" : "%d TEST(S) FAILED\n", failures);

	dlclose(h);
	return failures;
}
