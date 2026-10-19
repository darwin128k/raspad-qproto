#pragma once

#include <cstdint>

// HLDS engine_i486.so layouts qproto has been measured against (DWARF).
// classic: Aug 2018 / build 8684-era — Steam_NotifyClientConnect is a dynamic export,
//          client_t::network_userid @ 0x4a90.
// build10211: Oct 2024 build 10211 — same symbols exist but are local (.symtab only),
//          client_t::network_userid @ 0x6200. netchan.remote_address stays @ +0x20.
enum QprotoEngineLayout
{
	QPROTO_LAYOUT_AUTO = 0,
	QPROTO_LAYOUT_CLASSIC = 1,
	QPROTO_LAYOUT_BUILD10211 = 2,
};

struct QprotoEngineLayoutInfo
{
	QprotoEngineLayout layout;
	uintptr_t networkUseridOffset;
	uintptr_t remoteAddressOffset; // client_t::netchan.remote_address
	const char* name;
};

// Resolve a symbol inside the already-loaded engine_i486.so.
// Tries dlsym (dynsym) first; on failure walks the on-disk ELF .symtab so local
// symbols (build 10211) still resolve. Sets *outViaDynsym when non-null.
void* Qproto_Engine_Resolve(const char* symbol, bool* outViaDynsym = nullptr);

// Pick layout from config override or from how Resolve found the primary hook symbol.
const QprotoEngineLayoutInfo& Qproto_Engine_SelectLayout(QprotoEngineLayout overrideLayout, bool resolvedViaDynsym);

const char* Qproto_Engine_LayoutName(QprotoEngineLayout layout);
