#pragma once

#include "qproto/qproto_shared.h"
#include "qproto/qproto_engine.h"

struct QprotoConfig
{
	// Which client_t / export layout to use when hooking engine_i486.so.
	// auto (default): dynsym hit ⇒ classic (8684/2018); .symtab-only ⇒ build10211.
	// Force with EngineLayout=classic or EngineLayout=10211 in qproto.cfg.
	QprotoEngineLayout engineLayout = QPROTO_LAYOUT_AUTO;

	// Per-emulator on/off switches, mirroring dproto.cfg's cid_* style.
	bool enableRevEmu = true;      // RevEmu >= 9.74 (152-byte "rev"-signed ticket)
	bool enableRevEmu2013 = true;  // RevEmu2013 (194-byte, AES+SHA256)
	bool enableSC2009 = true;      // SteamClient 2009 (178-byte, AES+SHA256)
	bool enableOldRevEmu = true;   // legacy 10-byte XOR ticket
	bool enableSXEI = true;        // sXe Injected anti-cheat hardware id ("*HID" userinfo key)
	bool enableVellum = false;     // VLLM ticket — opt-in via EnableVellum=1 in qproto.cfg

	// cid_* (client_id_kind, same numbering/meaning as dproto.cfg's cid_RevEmu etc. -
	// see qproto_shared.h): which id format a *successfully authorized* client of
	// that emulator/auth-kind gets written as. Only CI_REAL_STEAM(1)/CI_REAL_VALVE(2)/
	// CI_HLTV(7)/CI_STEAM_ID_PENDING(9) map to something the engine's own native
	// SV_GetIDString can render for us directly (we write into
	// client_t::network_userid and let the unmodified engine format it - see
	// qproto_hook.cpp - rather than building the ID string ourselves the way classic plugins
	// does with full ReHLDS hook access); CI_STEAM_BY_IP(3)/CI_VALVE_BY_IP(4) are
	// handled specially in the hook (steamId is recomputed from the client's IP,
	// same as classic SteamByIp()); CI_DEPRECATED(5) rejects the connection.
	client_id_kind cidRevEmu = CI_REAL_STEAM;
	client_id_kind cidRevEmu2013 = CI_REAL_STEAM;
	client_id_kind cidSC2009 = CI_REAL_STEAM;
	client_id_kind cidOldRevEmu = CI_REAL_STEAM;
	client_id_kind cidSXEI = CI_REAL_STEAM;
	client_id_kind cidVellum = CI_REAL_STEAM;

	// Non-emulator client_auth_kind cases, from classic HLDS auth client_auth.cpp
	// (Setti authorizer/CNoSteam47/48Authorizer + the CA_STEAM_PENDING reclassification
	// in finish-client-auth). Classic plugins also have a cid_HLTV equivalent - not ported,
	// see qproto_shared.h's comment on CA_HLTV's removal for why it can't ever apply here.
	client_id_kind cidSetti = CI_STEAM_BY_IP;           // Setti monitoring bot - let it in, don't reject
	client_id_kind cidNoSteam47 = CI_DEPRECATED;        // no ticket at all, protocol 47 - reject by default
	client_id_kind cidNoSteam48 = CI_DEPRECATED;        // no ticket at all, protocol 48 - reject by default
	client_id_kind cidSteamPending = CI_STEAM_ID_PENDING; // any numeric auth kind (incl. real Steam) resolved to steamId 0/1

	// cid_Steam: applied even to clients who passed the engine's own *native* Steam
	// check (classic client_auth.cpp runs CA_STEAM through the exact same idkind
	// switch as every emulator). Default CI_REAL_STEAM is a deliberate no-op - leaves
	// native auth untouched. CI_STEAM_BY_IP/CI_VALVE_BY_IP are supported (recompute the
	// id from the client's IP, same as any other cid_*) - these are the only other
	// values Qproto_Cfg_Load() will accept for this key; anything else (notably
	// CI_DEPRECATED) is clamped back to CI_REAL_STEAM there, because qproto can't
	// safely reject a client the engine already authenticated via Steam - full engine hooks can,
	// but only because it also calls ISteamGameServer::SendUserDisconnect via ReHLDS's
	// exposed Steam API, an interface stock HLDS doesn't hand Metamod at all.
	client_id_kind cidSteam = CI_REAL_STEAM;

	// LoggingMode (0/1/2/3, default 2): same bitmask as dproto.cfg - rl_none=0,
	// rl_console=1, rl_logfile=2, rl_console|rl_logfile=3. Read before the log file
	// is opened, so with bit rl_logfile unset the file is never even created/touched.
	int loggingMode = rl_logfile;

};

extern QprotoConfig g_qprotoConfig;

void Qproto_Cfg_Load();
