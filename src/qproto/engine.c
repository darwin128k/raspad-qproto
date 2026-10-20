#define _GNU_SOURCE

#include "qproto/engine.h"
#include "qproto/logger.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const char g_engine_soname[] = "engine_i486.so";

typedef struct module_info {
	uintptr_t base;
	char path[512];
} module_info_t;

static int
find_engine_module(struct dl_phdr_info *info, size_t size, void *data)
{
	module_info_t *out = (module_info_t *)data;
	const char *base_name;

	(void)size;

	if (!info->dlpi_name || !info->dlpi_name[0])
		return 0;
	base_name = strrchr(info->dlpi_name, '/');
	base_name = base_name ? base_name + 1 : info->dlpi_name;
	if (strcmp(base_name, g_engine_soname) != 0)
		return 0;
	out->base = (uintptr_t)info->dlpi_addr;
	snprintf(out->path, sizeof(out->path), "%s", info->dlpi_name);
	return 1; /* stop */
}

static int
read_all(int fd, void *buf, size_t n)
{
	uint8_t *p = (uint8_t *)buf;
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r <= 0)
			return 0;
		got += (size_t)r;
	}
	return 1;
}

static void *
resolve_from_symtab(const module_info_t *mod, const char *symbol)
{
	int fd;
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdrs;
	const Elf32_Shdr *symtab;
	const Elf32_Shdr *strtab;
	void *result;
	int i;

	if (!mod->path[0])
		return NULL;

	fd = open(mod->path, O_RDONLY);
	if (fd < 0) {
		authum_logger_info(&g_qproto_logger, "engine resolve: open(%s) failed", mod->path);
		return NULL;
	}

	memset(&ehdr, 0, sizeof(ehdr));
	if (!read_all(fd, &ehdr, sizeof(ehdr)) ||
	    memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		close(fd);
		authum_logger_info(&g_qproto_logger, "engine resolve: %s is not ELF32", mod->path);
		return NULL;
	}

	if (lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET) < 0) {
		close(fd);
		return NULL;
	}

	shdrs = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
	if (!shdrs) {
		close(fd);
		return NULL;
	}
	if (!read_all(fd, shdrs, sizeof(Elf32_Shdr) * ehdr.e_shnum)) {
		free(shdrs);
		close(fd);
		return NULL;
	}

	symtab = NULL;
	strtab = NULL;
	for (i = 0; i < ehdr.e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_SYMTAB) {
			symtab = &shdrs[i];
			if (shdrs[i].sh_link < ehdr.e_shnum)
				strtab = &shdrs[shdrs[i].sh_link];
			break;
		}
	}

	result = NULL;
	if (symtab && strtab && symtab->sh_entsize == sizeof(Elf32_Sym)) {
		const size_t nsym = symtab->sh_size / sizeof(Elf32_Sym);
		Elf32_Sym *syms = (Elf32_Sym *)malloc(sizeof(Elf32_Sym) * nsym);
		char *strs = (char *)malloc(strtab->sh_size);
		int ok;

		if (!syms || !strs) {
			free(strs);
			free(syms);
			free(shdrs);
			close(fd);
			return NULL;
		}

		ok = lseek(fd, (off_t)symtab->sh_offset, SEEK_SET) >= 0 &&
			read_all(fd, syms, symtab->sh_size) &&
			lseek(fd, (off_t)strtab->sh_offset, SEEK_SET) >= 0 &&
			read_all(fd, strs, strtab->sh_size);

		if (ok) {
			size_t si;
			for (si = 0; si < nsym; si++) {
				if (syms[si].st_name == 0 || syms[si].st_value == 0)
					continue;
				if (syms[si].st_name >= strtab->sh_size)
					continue;
				if (strcmp(strs + syms[si].st_name, symbol) != 0)
					continue;
				/* ET_DYN: st_value is relative to load bias (dlpi_addr). */
				result = (void *)(mod->base + syms[si].st_value);
				authum_logger_info(&g_qproto_logger, "engine resolve: %s via .symtab @ %p (base=%p + 0x%x)",
					symbol, result, (void *)mod->base, (unsigned)syms[si].st_value);
				break;
			}
		}

		free(strs);
		free(syms);
	}

	free(shdrs);
	close(fd);
	return result;
}

static const qproto_engine_layout_info_t g_classic = {
	qproto_engine_layout_classic,
	0x4a90u, /* DWARF: network_userid @ 19088 */
	0x20u,   /* netchan @ 0x1c + remote_address @ +4 */
	"classic (8684/2018-era)"
};

static const qproto_engine_layout_info_t g_build10211 = {
	qproto_engine_layout_build10211,
	0x6200u, /* DWARF: network_userid @ 25088 */
	0x20u,   /* netchan still @ 0x1c + remote_address @ +4 */
	"build10211 (Oct 2024)"
};

void *
qproto_engine_resolve(const char *symbol, int *out_via_dynsym)
{
	void *eng;
	void *dyn;
	const char *err;
	module_info_t mod;

	if (out_via_dynsym)
		*out_via_dynsym = 0;

	eng = dlopen(g_engine_soname, RTLD_NOW | RTLD_NOLOAD);
	if (!eng) {
		authum_logger_info(&g_qproto_logger, "engine resolve: dlopen(%s, RTLD_NOLOAD) failed: %s", g_engine_soname, dlerror());
		return NULL;
	}

	dlerror();
	dyn = dlsym(eng, symbol);
	if (dyn) {
		authum_logger_info(&g_qproto_logger, "engine resolve: %s via dlsym @ %p", symbol, dyn);
		if (out_via_dynsym)
			*out_via_dynsym = 1;
		return dyn;
	}
	err = dlerror();
	authum_logger_info(&g_qproto_logger, "engine resolve: dlsym(%s) missed (%s) - trying .symtab", symbol, err ? err : "nil");

	memset(&mod, 0, sizeof(mod));
	dl_iterate_phdr(find_engine_module, &mod);
	if (!mod.base) {
		authum_logger_info(&g_qproto_logger, "engine resolve: dl_iterate_phdr did not find %s", g_engine_soname);
		return NULL;
	}
	return resolve_from_symtab(&mod, symbol);
}

const qproto_engine_layout_info_t *
qproto_engine_select_layout(qproto_engine_layout_t override_layout, int resolved_via_dynsym)
{
	if (override_layout == qproto_engine_layout_classic)
		return &g_classic;
	if (override_layout == qproto_engine_layout_build10211)
		return &g_build10211;

	/* AUTO: dynsym hit ⇒ classic export style; symtab-only ⇒ 10211-style locals. */
	return resolved_via_dynsym ? &g_classic : &g_build10211;
}

const char *
qproto_engine_layout_name(qproto_engine_layout_t layout)
{
	switch (layout) {
	case qproto_engine_layout_classic: return "classic";
	case qproto_engine_layout_build10211: return "10211";
	default: return "auto";
	}
}
