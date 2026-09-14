#pragma once

struct QprotoConfig
{
	// Per-emulator on/off switches, mirroring dproto.cfg's cid_* style. All default
	// to on except AllowIPFallback, which is a different kind of thing entirely (see
	// below) and defaults to off.
	bool enableRevEmu = true;      // RevEmu >= 9.74 (152-byte "rev"-signed ticket)
	bool enableRevEmu2013 = true;  // RevEmu2013 (194-byte, AES+SHA256)
	bool enableSC2009 = true;      // SteamClient 2009 (178-byte, AES+SHA256)
	bool enableOldRevEmu = true;   // legacy 10-byte XOR ticket

	// EnableLogging (0/1, default 1): write cstrike/addons/qproto/qproto.log at all.
	// Read before the log file is opened, so when this is 0 the file is never even
	// created/touched.
	bool enableLogging = true;

	// AllowIPFallback (0/1, default 0): when a client fails native Steam validation
	// and its ticket doesn't match any *enabled* format above, assign it a synthetic
	// IP-based SteamID instead of rejecting it - same idea as dproto.cfg's
	// cid_NoSteam47/48=4 (VALVE_by_IP). Off by default because, unlike a recognized
	// ticket, this accepts *any* client whose real Steam check failed, not
	// specifically RevEmu users - an admin decision, not a safe default.
	bool allowIpFallback = false;
};

extern QprotoConfig g_qprotoConfig;

void Qproto_Cfg_Load();
