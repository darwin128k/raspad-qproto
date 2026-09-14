#pragma once

#include "qproto/qproto_shared.h"

struct QprotoConfig
{
	// Per-emulator on/off switches, mirroring dproto.cfg's cid_* style. All default
	// to on except AllowIPFallback, which is a different kind of thing entirely (see
	// below) and defaults to off.
	bool enableRevEmu = true;      // RevEmu >= 9.74 (152-byte "rev"-signed ticket)
	bool enableRevEmu2013 = true;  // RevEmu2013 (194-byte, AES+SHA256)
	bool enableSC2009 = true;      // SteamClient 2009 (178-byte, AES+SHA256)
	bool enableOldRevEmu = true;   // legacy 10-byte XOR ticket

	// cid_* (client_id_kind, same numbering/meaning as dproto.cfg's cid_RevEmu etc. -
	// see qproto_shared.h): which id format a *successfully authorized* client of
	// that emulator gets written as. Only CI_REAL_STEAM(1) and CI_REAL_VALVE(2) map
	// to something the engine's own SV_GetIDString can actually render for us (we
	// write into client_t::network_userid and let the unmodified engine format it -
	// see qproto_hook.cpp - rather than building the ID string ourselves the way
	// classic does with full ReHLDS hook access). Anything else falls back to
	// CI_REAL_VALVE; CI_DEPRECATED(5) rejects the connection instead.
	client_id_kind cidRevEmu = CI_REAL_STEAM;
	client_id_kind cidRevEmu2013 = CI_REAL_STEAM;
	client_id_kind cidSC2009 = CI_REAL_STEAM;
	client_id_kind cidOldRevEmu = CI_REAL_STEAM;
	client_id_kind cidIPFallback = CI_VALVE_BY_IP; // matches dproto.cfg's cid_NoSteam47/48=4 default

	// LoggingMode (0/1/2/3, default 2): same bitmask as dproto.cfg - rl_none=0,
	// rl_console=1, rl_logfile=2, rl_console|rl_logfile=3. Read before the log file
	// is opened, so with bit rl_logfile unset the file is never even created/touched.
	int loggingMode = rl_logfile;

	// AllowIPFallback (0/1, default 0): when a client fails native Steam validation
	// and its ticket doesn't match any *enabled* format above, assign it a synthetic
	// IP-based SteamID (idtype from cidIPFallback above) instead of rejecting it -
	// same idea as dproto.cfg's cid_NoSteam47/48=4 (VALVE_by_IP). Off by default
	// because, unlike a recognized ticket, this accepts *any* client whose real
	// Steam check failed, not specifically RevEmu users - an admin decision, not a
	// safe default.
	bool allowIpFallback = false;
};

extern QprotoConfig g_qprotoConfig;

void Qproto_Cfg_Load();
