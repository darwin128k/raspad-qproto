#pragma once

#include "qproto/qproto_shared.h"

struct QprotoConfig
{
	// Per-emulator on/off switches, mirroring dproto.cfg's cid_* style.
	bool enableRevEmu = true;      // RevEmu >= 9.74 (152-byte "rev"-signed ticket)
	bool enableRevEmu2013 = true;  // RevEmu2013 (194-byte, AES+SHA256)
	bool enableSC2009 = true;      // SteamClient 2009 (178-byte, AES+SHA256)
	bool enableOldRevEmu = true;   // legacy 10-byte XOR ticket

	// cid_* (client_id_kind, same numbering/meaning as dproto.cfg's cid_RevEmu etc. -
	// see qproto_shared.h): which id format a *successfully authorized* client of
	// that emulator/auth-kind gets written as. Only CI_REAL_STEAM(1)/CI_REAL_VALVE(2)/
	// CI_HLTV(7)/CI_STEAM_ID_PENDING(9) map to something the engine's own native
	// SV_GetIDString can render for us directly (we write into
	// client_t::network_userid and let the unmodified engine format it - see
	// qproto_hook.cpp - rather than building the ID string ourselves the way classic
	// does with full ReHLDS hook access); CI_STEAM_BY_IP(3)/CI_VALVE_BY_IP(4) are
	// handled specially in the hook (steamId is recomputed from the client's IP,
	// same as classic's SteamByIp()); CI_DEPRECATED(5) rejects the connection.
	client_id_kind cidRevEmu = CI_REAL_STEAM;
	client_id_kind cidRevEmu2013 = CI_REAL_STEAM;
	client_id_kind cidSC2009 = CI_REAL_STEAM;
	client_id_kind cidOldRevEmu = CI_REAL_STEAM;

	// Non-emulator client_auth_kind cases, ported from classic's client_auth.cpp
	// (CHLTVAuthorizer/CSettiAuthorizer/CNoSteam47/48Authorizer + the CA_STEAM_PENDING
	// reclassification in classic_FinishClientAuth):
	client_id_kind cidHLTV = CI_HLTV;                  // HLTV proxy (userinfo "*hltv" key)
	client_id_kind cidSetti = CI_STEAM_BY_IP;           // Setti monitoring bot - let it in, don't reject
	client_id_kind cidNoSteam47 = CI_DEPRECATED;        // no ticket at all, protocol 47 - reject by default
	client_id_kind cidNoSteam48 = CI_DEPRECATED;        // no ticket at all, protocol 48 - reject by default
	client_id_kind cidSteamPending = CI_STEAM_ID_PENDING; // RevEmu/OldRevEmu resolved to steamId 0/1 (client's HDD serial unavailable)

	// LoggingMode (0/1/2/3, default 2): same bitmask as dproto.cfg - rl_none=0,
	// rl_console=1, rl_logfile=2, rl_console|rl_logfile=3. Read before the log file
	// is opened, so with bit rl_logfile unset the file is never even created/touched.
	int loggingMode = rl_logfile;
};

extern QprotoConfig g_qprotoConfig;

void Qproto_Cfg_Load();
