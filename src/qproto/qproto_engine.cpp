#include "qproto/qproto_engine.h"
#include "qproto/qproto_log.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace {

const char kEngineSoname[] = "engine_i486.so";

struct ModuleInfo
{
	uintptr_t base = 0;
	char path[512] = {};
};

int FindEngineModule(struct dl_phdr_info* info, size_t /*size*/, void* data)
{
	auto* out = static_cast<ModuleInfo*>(data);
	if (!info->dlpi_name || !info->dlpi_name[0])
		return 0;
	const char* baseName = strrchr(info->dlpi_name, '/');
	baseName = baseName ? baseName + 1 : info->dlpi_name;
	if (strcmp(baseName, kEngineSoname) != 0)
		return 0;
	out->base = static_cast<uintptr_t>(info->dlpi_addr);
	snprintf(out->path, sizeof(out->path), "%s", info->dlpi_name);
	return 1; // stop
}

bool ReadAll(int fd, void* buf, size_t n)
{
	auto* p = static_cast<uint8_t*>(buf);
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r <= 0)
			return false;
		got += static_cast<size_t>(r);
	}
	return true;
}

void* ResolveFromSymtab(const ModuleInfo& mod, const char* symbol)
{
	if (!mod.path[0])
		return nullptr;

	int fd = open(mod.path, O_RDONLY);
	if (fd < 0) {
		qproto_log("engine resolve: open(%s) failed", mod.path);
		return nullptr;
	}

	Elf32_Ehdr ehdr{};
	if (!ReadAll(fd, &ehdr, sizeof(ehdr)) ||
		memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		close(fd);
		qproto_log("engine resolve: %s is not ELF32", mod.path);
		return nullptr;
	}

	if (lseek(fd, static_cast<off_t>(ehdr.e_shoff), SEEK_SET) < 0) {
		close(fd);
		return nullptr;
	}

	Elf32_Shdr* shdrs = new Elf32_Shdr[ehdr.e_shnum];
	if (!ReadAll(fd, shdrs, sizeof(Elf32_Shdr) * ehdr.e_shnum)) {
		delete[] shdrs;
		close(fd);
		return nullptr;
	}

	const Elf32_Shdr* symtab = nullptr;
	const Elf32_Shdr* strtab = nullptr;
	for (int i = 0; i < ehdr.e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_SYMTAB) {
			symtab = &shdrs[i];
			if (shdrs[i].sh_link < ehdr.e_shnum)
				strtab = &shdrs[shdrs[i].sh_link];
			break;
		}
	}

	void* result = nullptr;
	if (symtab && strtab && symtab->sh_entsize == sizeof(Elf32_Sym)) {
		const size_t nsym = symtab->sh_size / sizeof(Elf32_Sym);
		auto* syms = new Elf32_Sym[nsym];
		auto* strs = new char[strtab->sh_size];

		bool ok = lseek(fd, static_cast<off_t>(symtab->sh_offset), SEEK_SET) >= 0 &&
			ReadAll(fd, syms, symtab->sh_size) &&
			lseek(fd, static_cast<off_t>(strtab->sh_offset), SEEK_SET) >= 0 &&
			ReadAll(fd, strs, strtab->sh_size);

		if (ok) {
			for (size_t i = 0; i < nsym; i++) {
				if (syms[i].st_name == 0 || syms[i].st_value == 0)
					continue;
				if (syms[i].st_name >= strtab->sh_size)
					continue;
				if (strcmp(strs + syms[i].st_name, symbol) != 0)
					continue;
				// ET_DYN: st_value is relative to load bias (dlpi_addr).
				result = reinterpret_cast<void*>(mod.base + syms[i].st_value);
				qproto_log("engine resolve: %s via .symtab @ %p (base=%p + 0x%x)",
					symbol, result, (void*)mod.base, (unsigned)syms[i].st_value);
				break;
			}
		}

		delete[] strs;
		delete[] syms;
	}

	delete[] shdrs;
	close(fd);
	return result;
}

const qproto_engine_layout_info kClassic{
	QPROTO_LAYOUT_CLASSIC,
	0x4a90u, // DWARF: network_userid @ 19088
	0x20u,   // netchan @ 0x1c + remote_address @ +4
	"classic (8684/2018-era)"
};

const qproto_engine_layout_info kBuild10211{
	QPROTO_LAYOUT_BUILD10211,
	0x6200u, // DWARF: network_userid @ 25088
	0x20u,   // netchan still @ 0x1c + remote_address @ +4
	"build10211 (Oct 2024)"
};

} // namespace

void* qproto_engine_resolve(const char* symbol, bool* outViaDynsym)
{
	if (outViaDynsym)
		*outViaDynsym = false;

	void* eng = dlopen(kEngineSoname, RTLD_NOW | RTLD_NOLOAD);
	if (!eng) {
		qproto_log("engine resolve: dlopen(%s, RTLD_NOLOAD) failed: %s", kEngineSoname, dlerror());
		return nullptr;
	}

	dlerror();
	if (void* dyn = dlsym(eng, symbol)) {
		qproto_log("engine resolve: %s via dlsym @ %p", symbol, dyn);
		if (outViaDynsym)
			*outViaDynsym = true;
		return dyn;
	}
	const char* err = dlerror();
	qproto_log("engine resolve: dlsym(%s) missed (%s) - trying .symtab", symbol, err ? err : "nil");

	ModuleInfo mod;
	dl_iterate_phdr(FindEngineModule, &mod);
	if (!mod.base) {
		qproto_log("engine resolve: dl_iterate_phdr did not find %s", kEngineSoname);
		return nullptr;
	}
	return ResolveFromSymtab(mod, symbol);
}

const qproto_engine_layout_info& qproto_engine_select_layout(qproto_engine_layout overrideLayout, bool resolvedViaDynsym)
{
	if (overrideLayout == QPROTO_LAYOUT_CLASSIC)
		return kClassic;
	if (overrideLayout == QPROTO_LAYOUT_BUILD10211)
		return kBuild10211;

	// AUTO: dynsym hit ⇒ classic export style; symtab-only ⇒ 10211-style locals.
	return resolvedViaDynsym ? kClassic : kBuild10211;
}

const char* qproto_engine_layout_name(qproto_engine_layout layout)
{
	switch (layout) {
		case QPROTO_LAYOUT_CLASSIC: return "classic";
		case QPROTO_LAYOUT_BUILD10211: return "10211";
		default: return "auto";
	}
}
